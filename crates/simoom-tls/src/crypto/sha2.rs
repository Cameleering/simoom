//! SHA-256, SHA-384 and SHA-512 (FIPS 180-4), HMAC (RFC 2104) and HKDF (RFC 5869).
//!
//! SHA-256 uses the CPU's SHA instructions (SHA-NI, ARMv8 SHA-2) when present. Outputs are
//! fixed-size [`Output`] values, so hashing never allocates.

use simoom_sys::arch;

/// A digest of up to 64 bytes.
#[derive(Clone, Copy)]
pub struct Output {
    buf: [u8; 64],
    len: u8,
}

impl Output {
    fn new(bytes: &[u8]) -> Output {
        let mut buf = [0u8; 64];
        buf[..bytes.len()].copy_from_slice(bytes);
        Output { buf, len: bytes.len() as u8 }
    }
}

impl core::ops::Deref for Output {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }
}

impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl PartialEq for Output {
    fn eq(&self, o: &Output) -> bool {
        crate::util::ct_eq(self, o)
    }
}

impl core::fmt::Debug for Output {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&crate::util::hex(self))
    }
}

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

fn compress256_soft(state: &mut [u32; 8], blocks: &[u8]) {
    for block in blocks.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
}

fn compress256(state: &mut [u32; 8], blocks: &[u8]) {
    if !arch::sha256_blocks(state, blocks) {
        compress256_soft(state, blocks);
    }
}

const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

fn compress512(state: &mut [u64; 8], blocks: &[u8]) {
    for block in blocks.chunks_exact(128) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes(block[8 * i..8 * i + 8].try_into().unwrap());
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K512[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
}

/// Block buffering shared by the hash functions.
#[derive(Clone)]
struct Buf<const B: usize> {
    buf: [u8; B],
    len: usize,
    total: u128,
}

impl<const B: usize> Buf<B> {
    const fn new() -> Self {
        Buf { buf: [0; B], len: 0, total: 0 }
    }

    fn update(&mut self, mut data: &[u8], mut compress: impl FnMut(&[u8])) {
        self.total += data.len() as u128;
        if self.len > 0 {
            let n = (B - self.len).min(data.len());
            self.buf[self.len..self.len + n].copy_from_slice(&data[..n]);
            self.len += n;
            data = &data[n..];
            if self.len < B {
                return;
            }
            compress(&self.buf);
            self.len = 0;
        }
        let whole = data.len() - data.len() % B;
        if whole > 0 {
            compress(&data[..whole]);
        }
        let rest = &data[whole..];
        self.buf[..rest.len()].copy_from_slice(rest);
        self.len = rest.len();
    }

    /// Appends the padding and the bit length (`lenbytes` wide) and compresses.
    fn pad(&mut self, lenbytes: usize, mut compress: impl FnMut(&[u8])) {
        let bits = self.total * 8;
        self.buf[self.len] = 0x80;
        self.buf[self.len + 1..].fill(0);
        if self.len + 1 > B - lenbytes {
            compress(&self.buf);
            self.buf.fill(0);
        }
        let lb = bits.to_be_bytes();
        self.buf[B - lenbytes..].copy_from_slice(&lb[16 - lenbytes..]);
        compress(&self.buf);
    }
}

/// SHA-256.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: Buf<64>,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub const fn new() -> Sha256 {
        Sha256 {
            state: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
            buf: Buf::new(),
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        let st = &mut self.state;
        self.buf.update(data, |b| compress256(st, b));
    }
    pub fn finish(mut self) -> [u8; 32] {
        let st = &mut self.state;
        self.buf.pad(8, |b| compress256(st, b));
        let mut out = [0u8; 32];
        for (o, w) in out.chunks_exact_mut(4).zip(self.state) {
            o.copy_from_slice(&w.to_be_bytes());
        }
        out
    }
    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finish()
    }
}

/// SHA-512 core, also used (with another IV and a truncated output) for SHA-384.
#[derive(Clone)]
pub struct Sha512 {
    state: [u64; 8],
    buf: Buf<128>,
    out_words: usize,
}

const IV512: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1,
    0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];
const IV384: [u64; 8] = [
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31,
    0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
];

impl Sha512 {
    pub const fn new() -> Sha512 {
        Sha512 { state: IV512, buf: Buf::new(), out_words: 8 }
    }
    pub const fn new384() -> Sha512 {
        Sha512 { state: IV384, buf: Buf::new(), out_words: 6 }
    }
    pub fn update(&mut self, data: &[u8]) {
        let st = &mut self.state;
        self.buf.update(data, |b| compress512(st, b));
    }
    pub fn finish(mut self) -> Output {
        let st = &mut self.state;
        self.buf.pad(16, |b| compress512(st, b));
        let mut out = [0u8; 64];
        for (o, w) in out.chunks_exact_mut(8).zip(self.state) {
            o.copy_from_slice(&w.to_be_bytes());
        }
        Output::new(&out[..8 * self.out_words])
    }
    pub fn digest(data: &[u8]) -> [u8; 64] {
        let mut h = Sha512::new();
        h.update(data);
        let mut o = [0u8; 64];
        o.copy_from_slice(&h.finish());
        o
    }
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

/// A hash function chosen at run time (cipher suites, signature schemes, certificates).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

/// A running hash of a [`HashAlg`].
#[derive(Clone)]
pub enum Hasher {
    Sha256(Sha256),
    Sha512(Sha512),
}

impl Hasher {
    pub fn new(alg: HashAlg) -> Hasher {
        match alg {
            HashAlg::Sha256 => Hasher::Sha256(Sha256::new()),
            HashAlg::Sha384 => Hasher::Sha512(Sha512::new384()),
            HashAlg::Sha512 => Hasher::Sha512(Sha512::new()),
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
        }
    }
    pub fn finish(self) -> Output {
        match self {
            Hasher::Sha256(h) => Output::new(&h.finish()),
            Hasher::Sha512(h) => h.finish(),
        }
    }
    /// The digest of everything so far, leaving the hasher usable.
    pub fn current(&self) -> Output {
        self.clone().finish()
    }
}

impl HashAlg {
    pub const fn output_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }
    const fn block_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 64,
            _ => 128,
        }
    }
    pub fn hash(self, data: &[u8]) -> Output {
        let mut h = Hasher::new(self);
        h.update(data);
        h.finish()
    }
    /// HMAC over the concatenation of `parts`.
    pub fn hmac(self, key: &[u8], parts: &[&[u8]]) -> Output {
        let bl = self.block_len();
        let mut k = [0u8; 128];
        if key.len() > bl {
            let d = self.hash(key);
            k[..d.len()].copy_from_slice(&d);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut pad = [0u8; 128];
        for (p, x) in pad.iter_mut().zip(k.iter()) {
            *p = x ^ 0x36;
        }
        let mut inner = Hasher::new(self);
        inner.update(&pad[..bl]);
        for p in parts {
            inner.update(p);
        }
        let ih = inner.finish();
        for (p, x) in pad.iter_mut().zip(k.iter()) {
            *p = x ^ 0x5c;
        }
        let mut outer = Hasher::new(self);
        outer.update(&pad[..bl]);
        outer.update(&ih);
        crate::util::zeroize(&mut k);
        crate::util::zeroize(&mut pad);
        outer.finish()
    }
    /// HKDF-Extract; an empty salt means HashLen zero bytes.
    pub fn hkdf_extract(self, salt: &[u8], ikm: &[u8]) -> Output {
        let zeros = [0u8; 64];
        let salt = if salt.is_empty() { &zeros[..self.output_len()] } else { salt };
        self.hmac(salt, &[ikm])
    }
    /// HKDF-Expand into `out` (at most 255 * HashLen bytes).
    pub fn hkdf_expand(self, prk: &[u8], info: &[&[u8]], out: &mut [u8]) {
        assert!(out.len() <= 255 * self.output_len(), "HKDF output too long");
        let mut t = Output::new(&[]);
        for (i, chunk) in out.chunks_mut(self.output_len()).enumerate() {
            let ctr = [i as u8 + 1];
            let next = {
                let mut parts: Vec<&[u8]> = Vec::with_capacity(info.len() + 2);
                parts.push(&t);
                parts.extend_from_slice(info);
                parts.push(&ctr);
                self.hmac(prk, &parts)
            };
            chunk.copy_from_slice(&next[..chunk.len()]);
            t = next;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    #[test]
    fn sha256_vectors_hardware_and_soft() {
        let million = vec![b'a'; 1_000_000];
        for soft in [false, true] {
            let digest = |d: &[u8]| -> [u8; 32] {
                if soft {
                    let mut st = Sha256::new().state;
                    let mut b = Buf::<64>::new();
                    b.update(d, |x| compress256_soft(&mut st, x));
                    b.pad(8, |x| compress256_soft(&mut st, x));
                    let mut out = [0u8; 32];
                    for (o, w) in out.chunks_exact_mut(4).zip(st) {
                        o.copy_from_slice(&w.to_be_bytes());
                    }
                    out
                } else {
                    Sha256::digest(d)
                }
            };
            assert_eq!(hex(&digest(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
            assert_eq!(hex(&digest(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
            assert_eq!(
                hex(&digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
            );
            assert_eq!(hex(&digest(&million)), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
        }
        // Incremental updates across block boundaries, including the 55/56/64-byte padding edges.
        for len in [55usize, 56, 63, 64, 65, 119, 120, 1000] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut h = Sha256::new();
            for c in data.chunks(7) {
                h.update(c);
            }
            assert_eq!(h.finish(), Sha256::digest(&data));
        }
        let mut h = Sha256::new();
        for c in million.chunks(37) {
            h.update(c);
        }
        assert_eq!(hex(&h.finish()), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    #[test]
    fn sha384_sha512_vectors() {
        assert_eq!(
            hex(&HashAlg::Sha384.hash(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(
            hex(&HashAlg::Sha384.hash(b"")),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(
            hex(&HashAlg::Sha384.hash(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")),
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
        );
        assert_eq!(
            hex(&HashAlg::Sha512.hash(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        let data = vec![0x61u8; 1000];
        let mut h = Hasher::new(HashAlg::Sha512);
        for c in data.chunks(111) {
            h.update(c);
        }
        assert_eq!(h.finish(), HashAlg::Sha512.hash(&data));
    }

    #[test]
    fn hmac_rfc4231() {
        let key = [0x0bu8; 20];
        assert_eq!(
            hex(&HashAlg::Sha256.hmac(&key, &[b"Hi There"])),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&HashAlg::Sha384.hmac(&key, &[b"Hi ", b"There"])),
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
        );
        assert_eq!(
            hex(&HashAlg::Sha512.hmac(&key, &[b"Hi There"])),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
        assert_eq!(
            hex(&HashAlg::Sha256.hmac(b"Jefe", &[b"what do ya want for nothing?"])),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let key = [0xaau8; 131];
        assert_eq!(
            hex(&HashAlg::Sha256.hmac(&key, &[b"Test Using Larger Than Block-Size Key - Hash Key First"])),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn hkdf_rfc5869() {
        let ikm = [0x0bu8; 22];
        let prk = HashAlg::Sha256.hkdf_extract(&unhex("000102030405060708090a0b0c"), &ikm);
        assert_eq!(hex(&prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let mut okm = [0u8; 42];
        HashAlg::Sha256.hkdf_expand(&prk, &[&unhex("f0f1f2f3f4"), &unhex("f5f6f7f8f9")], &mut okm);
        assert_eq!(hex(&okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
        let prk = HashAlg::Sha256.hkdf_extract(&[], &ikm);
        assert_eq!(hex(&prk), "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
        HashAlg::Sha256.hkdf_expand(&prk, &[], &mut okm);
        assert_eq!(hex(&okm), "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
    }
}
