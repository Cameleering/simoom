//! Legacy primitives (feature `legacy`; **moves to ksar**). Ported from Cameleer's
//! `cameleer-tls/src/crypto/{aes,des,rc2,md5}.rs` with their test vectors.
//!
//! Block ciphers and a digest that only key-store formats still use: AES with its inverse
//! cipher (for PBES2 AES-CBC), DES and Triple-DES (PKCS#12 `pbeWithSHAAnd3-KeyTripleDES-CBC`,
//! PBES2 `des-ede3-cbc`, JCEKS `PBEWithMD5AndTripleDES`), RC2 (PKCS#12
//! `pbeWithSHAAnd40BitRC2-CBC`) and MD5 (the JCEKS key derivation), plus CBC with PKCS#7
//! padding. MD4 (`md4.rs`, RFC 1320) and HMAC over MD5 and MD4 serve NTLM client
//! authentication.
//!
//! Nothing here is ever used by the TLS handshake or record layer. The AES here is bitsliced
//! and constant time (no table lookups indexed by secret data), like the rest of the crate.
//! DES, RC2 and MD5 are **table-driven and not constant time**: they exist only to read (and,
//! under the explicit legacy PKCS#12 profile or for JCEKS, to write) password-protected
//! key-store data, where the attacker model is offline password guessing, not cache timing.

use crate::util::zeroize;

mod md4;
pub use md4::Md4;

/// A 64- or 128-bit block cipher usable in CBC mode.
pub trait BlockCipher {
    const BLOCK: usize;
    fn encrypt(&self, block: &mut [u8]);
    fn decrypt(&self, block: &mut [u8]);
}

/// CBC encryption with PKCS#7 padding.
pub fn cbc_encrypt<C: BlockCipher>(c: &C, iv: &[u8], data: &[u8]) -> Vec<u8> {
    let bs = C::BLOCK;
    assert_eq!(iv.len(), bs, "CBC IV length");
    let pad = bs - data.len() % bs;
    let mut buf = data.to_vec();
    buf.extend(std::iter::repeat_n(pad as u8, pad));
    let mut prev = iv.to_vec();
    for chunk in buf.chunks_mut(bs) {
        for (b, p) in chunk.iter_mut().zip(&prev) {
            *b ^= p;
        }
        c.encrypt(chunk);
        prev.copy_from_slice(chunk);
    }
    buf
}

/// CBC decryption removing PKCS#7 padding (None on a length or padding error).
pub fn cbc_decrypt<C: BlockCipher>(c: &C, iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let bs = C::BLOCK;
    if data.is_empty() || !data.len().is_multiple_of(bs) || iv.len() != bs {
        return None;
    }
    let mut out = data.to_vec();
    let mut prev = iv.to_vec();
    let mut saved = vec![0u8; bs];
    for chunk in out.chunks_mut(bs) {
        saved.copy_from_slice(chunk);
        c.decrypt(chunk);
        for (b, p) in chunk.iter_mut().zip(&prev) {
            *b ^= p;
        }
        prev.copy_from_slice(&saved);
    }
    // Padding check without an early exit on the content.
    let pad = *out.last()? as usize;
    let mut bad = (pad == 0 || pad > bs) as u8;
    if bad == 0 {
        for b in &out[out.len() - pad..] {
            bad |= (*b as usize != pad) as u8;
        }
    }
    if bad != 0 {
        zeroize(&mut out);
        return None;
    }
    out.truncate(out.len() - pad);
    Some(out)
}

// ------------------------------------------------------------------ AES (bitsliced)

/// Bitsliced state: plane j holds bit j of each lane (byte).
type Planes = [u16; 8];

fn pack(bytes: &[u8]) -> Planes {
    let mut p = [0u16; 8];
    for (i, b) in bytes.iter().enumerate() {
        for (j, plane) in p.iter_mut().enumerate() {
            *plane |= (((*b >> j) & 1) as u16) << i;
        }
    }
    p
}

fn unpack(p: &Planes, bytes: &mut [u8]) {
    for (i, b) in bytes.iter_mut().enumerate() {
        let mut v = 0u8;
        for (j, plane) in p.iter().enumerate() {
            v |= (((plane >> i) & 1) as u8) << j;
        }
        *b = v;
    }
}

fn reduce(mut p: [u16; 15]) -> Planes {
    for k in (8..15).rev() {
        let t = p[k];
        p[k - 4] ^= t;
        p[k - 5] ^= t;
        p[k - 7] ^= t;
        p[k - 8] ^= t;
    }
    [p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]]
}

/// Bitsliced GF(2^8) multiplication modulo x^8 + x^4 + x^3 + x + 1.
fn bs_mul(a: &Planes, b: &Planes) -> Planes {
    let mut p = [0u16; 15];
    for i in 0..8 {
        for j in 0..8 {
            p[i + j] ^= a[i] & b[j];
        }
    }
    reduce(p)
}

/// Bitsliced squaring (linear over GF(2)).
fn bs_sq(a: &Planes) -> Planes {
    let mut p = [0u16; 15];
    for i in 0..8 {
        p[2 * i] = a[i];
    }
    reduce(p)
}

/// x^254 (= x^-1, with 0 -> 0).
fn bs_inv(x: &Planes) -> Planes {
    let x3 = bs_mul(&bs_sq(x), x);
    let x7 = bs_mul(&bs_sq(&x3), x);
    let x15 = bs_mul(&bs_sq(&x7), x);
    let x31 = bs_mul(&bs_sq(&x15), x);
    let x63 = bs_mul(&bs_sq(&x31), x);
    let x127 = bs_mul(&bs_sq(&x63), x);
    bs_sq(&x127)
}

fn lane_mask(n: usize) -> u16 {
    if n >= 16 {
        0xffff
    } else {
        (1u16 << n) - 1
    }
}

/// Constant-time SubBytes of up to 16 bytes.
fn sub_bytes_ct(bytes: &mut [u8]) {
    let mask = lane_mask(bytes.len());
    let b = bs_inv(&pack(bytes));
    let mut s = [0u16; 8];
    for i in 0..8 {
        s[i] = b[i] ^ b[(i + 7) % 8] ^ b[(i + 6) % 8] ^ b[(i + 5) % 8] ^ b[(i + 4) % 8];
        if (0x63 >> i) & 1 == 1 {
            s[i] ^= mask;
        }
    }
    unpack(&s, bytes);
}

/// Constant-time InvSubBytes of up to 16 bytes.
fn inv_sub_bytes_ct(bytes: &mut [u8]) {
    let mask = lane_mask(bytes.len());
    let s = pack(bytes);
    let mut b = [0u16; 8];
    for i in 0..8 {
        b[i] = s[(i + 7) % 8] ^ s[(i + 5) % 8] ^ s[(i + 2) % 8];
        if (0x05 >> i) & 1 == 1 {
            b[i] ^= mask;
        }
    }
    unpack(&bs_inv(&b), bytes);
}

#[inline]
fn xtime(b: u8) -> u8 {
    (b << 1) ^ (((b >> 7) & 1) * 0x1b)
}

/// Branch-free GF(2^8) multiplication (used with secret `a`).
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        p ^= a & (b & 1).wrapping_neg();
        a = xtime(a);
        b >>= 1;
    }
    p
}

/// AES-128/192/256 (FIPS-197), both directions, bitsliced S-box.
pub struct Aes {
    round_keys: Vec<[u8; 16]>,
}

impl Drop for Aes {
    fn drop(&mut self) {
        for k in self.round_keys.iter_mut() {
            zeroize(k);
        }
    }
}

impl Aes {
    /// `key` must be 16, 24 or 32 bytes.
    pub fn new(key: &[u8]) -> Aes {
        assert!(matches!(key.len(), 16 | 24 | 32), "AES key must be 16/24/32 bytes");
        let nk = key.len() / 4;
        let nr = nk + 6;
        let total = 4 * (nr + 1);
        let mut w: Vec<[u8; 4]> = Vec::with_capacity(total);
        for i in 0..nk {
            w.push([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        }
        let mut rcon = 1u8;
        for i in nk..total {
            let mut t = w[i - 1];
            if i % nk == 0 {
                let mut r = [t[1], t[2], t[3], t[0]];
                sub_bytes_ct(&mut r);
                r[0] ^= rcon;
                t = r;
                rcon = xtime(rcon);
            } else if nk > 6 && i % nk == 4 {
                sub_bytes_ct(&mut t);
            }
            let p = w[i - nk];
            w.push([p[0] ^ t[0], p[1] ^ t[1], p[2] ^ t[2], p[3] ^ t[3]]);
        }
        let round_keys = w
            .chunks(4)
            .map(|c| {
                let mut k = [0u8; 16];
                for (j, word) in c.iter().enumerate() {
                    k[4 * j..4 * j + 4].copy_from_slice(word);
                }
                k
            })
            .collect();
        for word in w.iter_mut() {
            zeroize(word);
        }
        Aes { round_keys }
    }

    pub fn encrypt_block(&self, s: &mut [u8; 16]) {
        let nr = self.round_keys.len() - 1;
        for (b, k) in s.iter_mut().zip(&self.round_keys[0]) {
            *b ^= k;
        }
        for round in 1..=nr {
            sub_bytes_ct(&mut s[..]);
            // ShiftRows (state is column-major: s[4*c + r])
            let t = *s;
            for c in 0..4 {
                for r in 0..4 {
                    s[4 * c + r] = t[4 * ((c + r) % 4) + r];
                }
            }
            if round != nr {
                for c in 0..4 {
                    let (a0, a1, a2, a3) = (s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]);
                    let all = a0 ^ a1 ^ a2 ^ a3;
                    s[4 * c] = a0 ^ all ^ xtime(a0 ^ a1);
                    s[4 * c + 1] = a1 ^ all ^ xtime(a1 ^ a2);
                    s[4 * c + 2] = a2 ^ all ^ xtime(a2 ^ a3);
                    s[4 * c + 3] = a3 ^ all ^ xtime(a3 ^ a0);
                }
            }
            for (b, k) in s.iter_mut().zip(&self.round_keys[round]) {
                *b ^= k;
            }
        }
    }

    /// The inverse cipher.
    pub fn decrypt_block(&self, s: &mut [u8; 16]) {
        let nr = self.round_keys.len() - 1;
        for (b, k) in s.iter_mut().zip(&self.round_keys[nr]) {
            *b ^= k;
        }
        for round in (0..nr).rev() {
            let t = *s;
            for c in 0..4 {
                for r in 0..4 {
                    s[4 * ((c + r) % 4) + r] = t[4 * c + r];
                }
            }
            inv_sub_bytes_ct(&mut s[..]);
            for (b, k) in s.iter_mut().zip(&self.round_keys[round]) {
                *b ^= k;
            }
            if round != 0 {
                for c in 0..4 {
                    let a = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
                    for r in 0..4 {
                        s[4 * c + r] = gmul(a[r], 14) ^ gmul(a[(r + 1) % 4], 11) ^ gmul(a[(r + 2) % 4], 13) ^ gmul(a[(r + 3) % 4], 9);
                    }
                }
            }
        }
    }
}

impl BlockCipher for Aes {
    const BLOCK: usize = 16;
    fn encrypt(&self, block: &mut [u8]) {
        let b: &mut [u8; 16] = block.try_into().expect("16-byte block");
        self.encrypt_block(b);
    }
    fn decrypt(&self, block: &mut [u8]) {
        let b: &mut [u8; 16] = block.try_into().expect("16-byte block");
        self.decrypt_block(b);
    }
}

// ------------------------------------------------------------------ DES / 3DES (table-driven)

const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33,
    25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];
const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12,
    52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];
const E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25,
    26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];
const P: [u8; 32] = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25];
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7,
    62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
];
const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];
const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
const S: [[u8; 64]; 8] = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11,
        15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1,
        5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0,
        11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13,
        15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8,
        15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3,
        7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14,
        10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2,
        0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

/// Permutes the `in_bits`-bit value `v` (bit 1 = most significant) by `table`.
fn permute(v: u64, in_bits: u32, table: &[u8]) -> u64 {
    let mut out = 0u64;
    for &t in table {
        out = (out << 1) | ((v >> (in_bits - t as u32)) & 1);
    }
    out
}

/// Single DES with a precomputed key schedule (table-driven, not constant time).
pub struct Des {
    subkeys: [u64; 16],
}

impl Drop for Des {
    fn drop(&mut self) {
        self.subkeys = [0; 16];
        core::hint::black_box(&self.subkeys);
    }
}

impl Des {
    /// The first 8 bytes of `key` (parity bits ignored).
    pub fn new(key: &[u8]) -> Des {
        let k = u64::from_be_bytes(key[..8].try_into().expect("8-byte DES key"));
        let cd = permute(k, 64, &PC1);
        let mut c = (cd >> 28) as u32 & 0x0fff_ffff;
        let mut d = cd as u32 & 0x0fff_ffff;
        let mut subkeys = [0u64; 16];
        for (i, s) in SHIFTS.iter().enumerate() {
            for _ in 0..*s {
                c = ((c << 1) | (c >> 27)) & 0x0fff_ffff;
                d = ((d << 1) | (d >> 27)) & 0x0fff_ffff;
            }
            subkeys[i] = permute(((c as u64) << 28) | d as u64, 56, &PC2);
        }
        Des { subkeys }
    }

    fn feistel(r: u32, k: u64) -> u32 {
        let x = permute(r as u64, 32, &E) ^ k;
        let mut out = 0u32;
        for (i, sbox) in S.iter().enumerate() {
            let six = ((x >> (42 - 6 * i)) & 0x3f) as usize;
            let row = ((six & 0x20) >> 4) | (six & 1);
            let col = (six >> 1) & 0xf;
            out = (out << 4) | sbox[row * 16 + col] as u32;
        }
        permute(out as u64, 32, &P) as u32
    }

    fn crypt(&self, block: u64, decrypt: bool) -> u64 {
        let ip = permute(block, 64, &IP);
        let mut l = (ip >> 32) as u32;
        let mut r = ip as u32;
        for i in 0..16 {
            let k = if decrypt { self.subkeys[15 - i] } else { self.subkeys[i] };
            let t = r;
            r = l ^ Des::feistel(r, k);
            l = t;
        }
        permute(((r as u64) << 32) | l as u64, 64, &FP)
    }
}

impl BlockCipher for Des {
    const BLOCK: usize = 8;
    fn encrypt(&self, block: &mut [u8]) {
        let v = self.crypt(u64::from_be_bytes(block[..8].try_into().expect("8-byte block")), false);
        block.copy_from_slice(&v.to_be_bytes());
    }
    fn decrypt(&self, block: &mut [u8]) {
        let v = self.crypt(u64::from_be_bytes(block[..8].try_into().expect("8-byte block")), true);
        block.copy_from_slice(&v.to_be_bytes());
    }
}

/// Triple DES in EDE mode with a 24-byte (three-key) or 16-byte (two-key) key.
pub struct TripleDes {
    k1: Des,
    k2: Des,
    k3: Des,
}

impl TripleDes {
    pub fn new(key: &[u8]) -> TripleDes {
        assert!(key.len() == 24 || key.len() == 16, "3DES key must be 16 or 24 bytes");
        let k3 = if key.len() == 24 { &key[16..24] } else { &key[..8] };
        TripleDes { k1: Des::new(&key[..8]), k2: Des::new(&key[8..16]), k3: Des::new(k3) }
    }
}

impl BlockCipher for TripleDes {
    const BLOCK: usize = 8;
    fn encrypt(&self, block: &mut [u8]) {
        let v = u64::from_be_bytes(block[..8].try_into().expect("8-byte block"));
        let v = self.k3.crypt(self.k2.crypt(self.k1.crypt(v, false), true), false);
        block.copy_from_slice(&v.to_be_bytes());
    }
    fn decrypt(&self, block: &mut [u8]) {
        let v = u64::from_be_bytes(block[..8].try_into().expect("8-byte block"));
        let v = self.k1.crypt(self.k2.crypt(self.k3.crypt(v, true), false), true);
        block.copy_from_slice(&v.to_be_bytes());
    }
}

// ------------------------------------------------------------------ RC2 (RFC 2268, table-driven)

const PITABLE: [u8; 256] = [
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d, 0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53,
    0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2, 0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81,
    0x7d, 0x32, 0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82, 0x54, 0xd6, 0x65, 0x93, 0xce,
    0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc, 0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30,
    0xa3, 0x3c, 0xb6, 0x26, 0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03, 0xf8, 0x11, 0xc7,
    0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7, 0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa,
    0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a, 0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec, 0xc2,
    0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39, 0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a,
    0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31, 0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba,
    0xc9, 0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9, 0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33,
    0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e, 0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe,
    0x7f, 0xc1, 0xad,
];

/// RC2 with an explicit effective key length in bits (table-driven, not constant time).
pub struct Rc2 {
    k: [u16; 64],
}

impl Drop for Rc2 {
    fn drop(&mut self) {
        self.k = [0; 64];
        core::hint::black_box(&self.k);
    }
}

impl Rc2 {
    /// `key` is 1..=128 bytes; `effective_bits` 1..=1024.
    pub fn new(key: &[u8], effective_bits: usize) -> Rc2 {
        let t = key.len();
        assert!((1..=128).contains(&t), "RC2 key length");
        assert!((1..=1024).contains(&effective_bits), "RC2 effective key bits");
        let mut l = [0u8; 128];
        l[..t].copy_from_slice(key);
        for i in t..128 {
            l[i] = PITABLE[(l[i - 1] as usize + l[i - t] as usize) & 0xff];
        }
        let t8 = effective_bits.div_ceil(8);
        let tm = (0xffu32 >> (8 * t8 - effective_bits)) as u8;
        l[128 - t8] = PITABLE[(l[128 - t8] & tm) as usize];
        for i in (0..128 - t8).rev() {
            l[i] = PITABLE[(l[i + 1] ^ l[i + t8]) as usize];
        }
        let mut k = [0u16; 64];
        for (i, kk) in k.iter_mut().enumerate() {
            *kk = l[2 * i] as u16 | (l[2 * i + 1] as u16) << 8;
        }
        zeroize(&mut l);
        Rc2 { k }
    }

    fn words(b: &[u8]) -> [u16; 4] {
        [u16::from_le_bytes([b[0], b[1]]), u16::from_le_bytes([b[2], b[3]]), u16::from_le_bytes([b[4], b[5]]), u16::from_le_bytes([b[6], b[7]])]
    }

    fn store(r: [u16; 4], b: &mut [u8]) {
        for i in 0..4 {
            b[2 * i..2 * i + 2].copy_from_slice(&r[i].to_le_bytes());
        }
    }
}

const ROT: [u32; 4] = [1, 2, 3, 5];

impl BlockCipher for Rc2 {
    const BLOCK: usize = 8;
    fn encrypt(&self, block: &mut [u8]) {
        let mut r = Rc2::words(block);
        let mut j = 0;
        for round in 0..16 {
            for i in 0..4 {
                r[i] = r[i]
                    .wrapping_add(self.k[j])
                    .wrapping_add(r[(i + 3) % 4] & r[(i + 2) % 4])
                    .wrapping_add(!r[(i + 3) % 4] & r[(i + 1) % 4]);
                j += 1;
                r[i] = r[i].rotate_left(ROT[i]);
            }
            if round == 4 || round == 10 {
                for i in 0..4 {
                    r[i] = r[i].wrapping_add(self.k[(r[(i + 3) % 4] & 63) as usize]);
                }
            }
        }
        Rc2::store(r, block);
    }
    fn decrypt(&self, block: &mut [u8]) {
        let mut r = Rc2::words(block);
        let mut j = 64usize;
        for round in (0..16).rev() {
            for i in (0..4).rev() {
                j -= 1;
                r[i] = r[i].rotate_right(ROT[i]);
                r[i] = r[i]
                    .wrapping_sub(self.k[j])
                    .wrapping_sub(r[(i + 3) % 4] & r[(i + 2) % 4])
                    .wrapping_sub(!r[(i + 3) % 4] & r[(i + 1) % 4]);
            }
            if round == 5 || round == 11 {
                for i in (0..4).rev() {
                    r[i] = r[i].wrapping_sub(self.k[(r[(i + 3) % 4] & 63) as usize]);
                }
            }
        }
        Rc2::store(r, block);
    }
}

// ------------------------------------------------------------------ MD5 (RFC 1321)

/// MD5, only for the JCEKS `PBEWithMD5AndTripleDES` key derivation.
pub struct Md5 {
    state: [u32; 4],
    buf: Vec<u8>,
    total: u64,
}

const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11,
    16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// floor(|sin(i + 1)| * 2^32), RFC 1321 section 3.4.
const MD5_K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1,
    0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453,
    0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942,
    0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d,
    0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

impl Md5 {
    pub fn new() -> Md5 {
        Md5 { state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476], buf: Vec::with_capacity(64), total: 0 }
    }

    fn compress(state: &mut [u32; 4], block: &[u8]) {
        let mut m = [0u32; 16];
        for (w, c) in m.iter_mut().zip(block.as_chunks::<4>().0) {
            *w = u32::from_le_bytes(*c);
        }
        let [mut a, mut b, mut c, mut d] = *state;
        for (i, shift) in MD5_S.iter().enumerate() {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let t = d;
            d = c;
            c = b;
            b = b.wrapping_add(a.wrapping_add(f).wrapping_add(MD5_K[i]).wrapping_add(m[g]).rotate_left(*shift));
            a = t;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        self.buf.extend_from_slice(data);
        let full = self.buf.len() / 64 * 64;
        for i in (0..full).step_by(64) {
            let mut block = [0u8; 64];
            block.copy_from_slice(&self.buf[i..i + 64]);
            Md5::compress(&mut self.state, &block);
        }
        self.buf.drain(..full);
    }

    pub fn finish(mut self) -> [u8; 16] {
        let bits = self.total.wrapping_mul(8);
        let mut pad = vec![0x80u8];
        while (self.buf.len() + pad.len()) % 64 != 56 {
            pad.push(0);
        }
        pad.extend_from_slice(&bits.to_le_bytes());
        self.update(&pad);
        let mut out = [0u8; 16];
        for (o, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            o.copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 16] {
        let mut h = Md5::new();
        h.update(data);
        h.finish()
    }
}

/// HMAC (RFC 2104) over a 64-byte-block legacy hash: `new`, `update`, `finish`.
macro_rules! legacy_hmac {
    ($name:ident, $hash:ty) => {
        /// HMAC over the concatenation of `parts`.
        pub fn $name(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
            let mut k = [0u8; 64];
            if key.len() > 64 {
                k[..16].copy_from_slice(&<$hash>::digest(key));
            } else {
                k[..key.len()].copy_from_slice(key);
            }
            let mut pad = [0u8; 64];
            for (p, b) in pad.iter_mut().zip(&k) {
                *p = b ^ 0x36;
            }
            let mut inner = <$hash>::new();
            inner.update(&pad);
            for p in parts {
                inner.update(p);
            }
            let ih = inner.finish();
            for (p, b) in pad.iter_mut().zip(&k) {
                *p = b ^ 0x5c;
            }
            let mut outer = <$hash>::new();
            outer.update(&pad);
            outer.update(&ih);
            crate::util::zeroize(&mut k);
            crate::util::zeroize(&mut pad);
            outer.finish()
        }
    };
}

legacy_hmac!(hmac_md5, Md5);
legacy_hmac!(hmac_md4, Md4);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    #[test]
    fn hmac_md5_rfc2202() {
        assert_eq!(hex(&hmac_md5(&[0x0b; 16], &[b"Hi There"])), "9294727a3638bb1c13f48ef8158bfc9d");
        assert_eq!(hex(&hmac_md5(b"Jefe", &[b"what do ya want ", b"for nothing?"])), "750c783e6ab0b503eaa86e310a5db738");
        assert_eq!(hex(&hmac_md5(&[0xaa; 16], &[&[0xdd; 50]])), "56be34521d144c88dbb8c733f0e8b3f6");
        // a key longer than the block is hashed first
        assert_eq!(hex(&hmac_md5(&[0xaa; 80], &[b"Test Using Larger Than Block-Size Key - Hash Key First"])), "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd");
        assert_eq!(
            hex(&hmac_md5(&[0xaa; 80], &[b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"])),
            "6f630fad67cda0ee1fb1f562db3aa53e"
        );
        // the NTLMv2 shape: HMAC-MD5 keyed with an MD4 output (MS-NLMP 4.2.4.1.1 NTOWFv2)
        let nt = Md4::digest(&"Password".encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<u8>>());
        let user_dom: Vec<u8> = "USERDomain".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(hex(&hmac_md5(&nt, &[&user_dom])), "0c868a403bfd7a93a3001ef22ef02e3f");
        let _ = unhex("00");
        assert_eq!(hmac_md4(b"k", &[b"m"]).len(), 16);
    }

    const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0u8;
        let mut i = 0;
        while i < 8 {
            if b & 1 != 0 {
                p ^= a;
            }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 {
                a ^= 0x1b;
            }
            b >>= 1;
            i += 1;
        }
        p
    }

    fn sbox(x: u8) -> u8 {
        let mut inv = 1u8;
        let mut base = x;
        let mut e = 254u32;
        while e > 0 {
            if e & 1 == 1 {
                inv = gf_mul(inv, base);
            }
            base = gf_mul(base, base);
            e >>= 1;
        }
        if x == 0 {
            inv = 0;
        }
        inv ^ inv.rotate_left(1) ^ inv.rotate_left(2) ^ inv.rotate_left(3) ^ inv.rotate_left(4) ^ 0x63
    }

    #[test]
    fn constant_time_sbox_matches_reference() {
        let mut all: Vec<u8> = (0..=255).collect();
        for chunk in all.chunks_mut(16) {
            let orig = chunk.to_vec();
            sub_bytes_ct(chunk);
            for (o, c) in orig.iter().zip(chunk.iter()) {
                assert_eq!(*c, sbox(*o));
            }
            let mut back = chunk.to_vec();
            inv_sub_bytes_ct(&mut back);
            assert_eq!(back, orig);
        }
        let mut short = [0x53u8, 0x00, 0xff];
        sub_bytes_ct(&mut short);
        assert_eq!(short, [0xed, 0x63, 0x16]);
        for a in 0..=255u8 {
            for b in [2u8, 3, 9, 11, 13, 14] {
                assert_eq!(gmul(a, b), gf_mul(a, b));
            }
        }
    }

    fn block(s: &str) -> [u8; 16] {
        unhex(s).try_into().unwrap()
    }

    #[test]
    fn aes_fips197_encrypt_and_decrypt() {
        // FIPS-197 appendix C.1-C.3 and appendix B
        let cases = [
            ("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"),
            ("000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"),
            ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
            ("2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734", "3925841d02dc09fbdc118597196a0b32"),
        ];
        for (key, pt, ct) in cases {
            let a = Aes::new(&unhex(key));
            let mut b = block(pt);
            a.encrypt_block(&mut b);
            assert_eq!(hex(&b), ct);
            a.decrypt_block(&mut b);
            assert_eq!(hex(&b), pt);
            let mut c = block(ct);
            a.decrypt_block(&mut c);
            assert_eq!(hex(&c), pt, "inverse cipher, key {key}");
        }
    }

    #[test]
    fn cbc_sp800_38a_and_padding() {
        // NIST SP 800-38A F.2.1 / F.2.5 (first block; our PKCS#7 padding adds a block)
        let iv = unhex("000102030405060708090a0b0c0d0e0f");
        let pt = unhex("6bc1bee22e409f96e93d7e117393172a");
        let a = Aes::new(&unhex("2b7e151628aed2a6abf7158809cf4f3c"));
        let ct = cbc_encrypt(&a, &iv, &pt);
        assert_eq!(ct.len(), 32);
        assert_eq!(hex(&ct[..16]), "7649abac8119b246cee98e9b12e9197d");
        assert_eq!(cbc_decrypt(&a, &iv, &ct).unwrap(), pt);
        let a = Aes::new(&unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"));
        let ct = cbc_encrypt(&a, &iv, &pt);
        assert_eq!(hex(&ct[..16]), "f58c4c04d6e5f1ba779eabfb5f7bfbd6");
        assert_eq!(cbc_decrypt(&a, &iv, &ct).unwrap(), pt);
        let mut bad = ct.clone();
        let n = bad.len();
        bad[n - 17] ^= 1; // flips the last plaintext byte (the padding)
        assert!(cbc_decrypt(&a, &iv, &bad).is_none());
        assert!(cbc_decrypt(&a, &iv, &ct[..31]).is_none());
        assert!(cbc_decrypt(&a, &iv[..8], &ct).is_none());
        assert!(cbc_decrypt(&a, &iv, &[]).is_none());
        for len in 0..40 {
            let data: Vec<u8> = (0..len as u8).collect();
            let t = TripleDes::new(&[7u8; 24]);
            assert_eq!(cbc_decrypt(&t, &[1; 8], &cbc_encrypt(&t, &[1; 8], &data)).unwrap(), data);
        }
    }

    #[test]
    fn des_known_answer() {
        // the classic worked example (key 133457799BBCDFF1)
        let d = Des::new(&unhex("133457799BBCDFF1"));
        let mut b = unhex("0123456789ABCDEF");
        d.encrypt(&mut b);
        assert_eq!(hex(&b), "85e813540f0ab405");
        d.decrypt(&mut b);
        assert_eq!(hex(&b), "0123456789abcdef");
        // FIPS 81 / NBS example: key 0123456789abcdef, "Now is t"
        let d = Des::new(&unhex("0123456789abcdef"));
        let mut b = b"Now is t".to_vec();
        d.encrypt(&mut b);
        assert_eq!(hex(&b), "3fa40e8a984d4815");
    }

    #[test]
    fn triple_des_known_answer() {
        // NIST SP 800-67 example: keys 0123456789ABCDEF 23456789ABCDEF01 456789ABCDEF0123
        let t = TripleDes::new(&unhex("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123"));
        let mut b = b"The qufc".to_vec();
        t.encrypt(&mut b);
        assert_eq!(hex(&b), "a826fd8ce53b855f");
        t.decrypt(&mut b);
        assert_eq!(&b, b"The qufc");
        // two-key 3DES with K1 = K2 = K3 is single DES
        let t = TripleDes::new(&unhex("133457799BBCDFF1133457799BBCDFF1"));
        let mut b = unhex("0123456789ABCDEF");
        t.encrypt(&mut b);
        assert_eq!(hex(&b), "85e813540f0ab405");
    }

    #[test]
    fn rc2_rfc2268_vectors() {
        let cases = [
            ("0000000000000000", 63, "0000000000000000", "ebb773f993278eff"),
            ("ffffffffffffffff", 64, "ffffffffffffffff", "278b27e42e2f0d49"),
            ("3000000000000000", 64, "1000000000000001", "30649edf9be7d2c2"),
            ("88", 64, "0000000000000000", "61a8a244adacccf0"),
            ("88bca90e90875a", 64, "0000000000000000", "6ccf4308974c267f"),
            ("88bca90e90875a7f0f79c384627bafb2", 64, "0000000000000000", "1a807d272bbe5db1"),
            ("88bca90e90875a7f0f79c384627bafb2", 128, "0000000000000000", "2269552ab0f85ca6"),
        ];
        for (key, bits, pt, ct) in cases {
            let c = Rc2::new(&unhex(key), bits);
            let mut b = unhex(pt);
            c.encrypt(&mut b);
            assert_eq!(hex(&b), ct, "key {key}");
            c.decrypt(&mut b);
            assert_eq!(hex(&b), pt);
        }
    }

        #[test]
    fn md5_rfc1321_vectors() {
        let cases = [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            ("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
            ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"),
            ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a"),
        ];
        for (m, d) in cases {
            assert_eq!(hex(&Md5::digest(m.as_bytes())), d, "{m:?}");
        }
        // split updates give the same digest
        let mut h = Md5::new();
        for b in b"message digest".chunks(3) {
            h.update(b);
        }
        assert_eq!(hex(&h.finish()), "f96b697d7cb7938d525a2f31aaf161d0");
    }
}
