//! MD4 (RFC 1320), feature `legacy`; **moves to ksar**. Only for NTLM (the NT hash and
//! NTLMv2 client authentication), which still require it. Broken as a hash: never use it for
//! anything else. Cameleer has no MD4, so this is new code, written like the MD5 next to it
//! and checked against all seven RFC 1320 test vectors. It has no secret-dependent branches or
//! table lookups (the round index alone selects the function and shift).

/// A running MD4 hash.
#[derive(Clone)]
pub struct Md4 {
    state: [u32; 4],
    buf: [u8; 64],
    buf_len: usize,
    total: u64,
}

impl Default for Md4 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md4 {
    pub const OUT_LEN: usize = 16;
    pub const BLOCK_LEN: usize = 64;

    pub const fn new() -> Md4 {
        Md4 { state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476], buf: [0; 64], buf_len: 0, total: 0 }
    }

    fn compress(state: &mut [u32; 4], block: &[u8]) {
        let mut x = [0u32; 16];
        for (i, w) in x.iter_mut().enumerate() {
            *w = u32::from_le_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
        }
        let [mut a, mut b, mut c, mut d] = *state;
        // round 1: F(x, y, z) = (x & y) | (!x & z)
        const S1: [u32; 4] = [3, 7, 11, 19];
        for i in 0..16 {
            let f = (b & c) | (!b & d);
            let t = a.wrapping_add(f).wrapping_add(x[i]).rotate_left(S1[i % 4]);
            (a, b, c, d) = (d, t, b, c);
        }
        // round 2: G(x, y, z) = (x & y) | (x & z) | (y & z), constant 0x5a827999
        const S2: [u32; 4] = [3, 5, 9, 13];
        for i in 0..16 {
            let k = (i % 4) * 4 + i / 4;
            let g = (b & c) | (b & d) | (c & d);
            let t = a.wrapping_add(g).wrapping_add(x[k]).wrapping_add(0x5a827999).rotate_left(S2[i % 4]);
            (a, b, c, d) = (d, t, b, c);
        }
        // round 3: H(x, y, z) = x ^ y ^ z, constant 0x6ed9eba1
        const S3: [u32; 4] = [3, 9, 11, 15];
        const K3: [usize; 16] = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
        for i in 0..16 {
            let h = b ^ c ^ d;
            let t = a.wrapping_add(h).wrapping_add(x[K3[i]]).wrapping_add(0x6ed9eba1).rotate_left(S3[i % 4]);
            (a, b, c, d) = (d, t, b, c);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let n = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + n].copy_from_slice(&data[..n]);
            self.buf_len += n;
            data = &data[n..];
            if self.buf_len == 64 {
                let b = self.buf;
                Self::compress(&mut self.state, &b);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            Self::compress(&mut self.state, &data[..64]);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finish(mut self) -> [u8; 16] {
        let bits = self.total.wrapping_mul(8);
        let mut pad = [0u8; 72];
        pad[0] = 0x80;
        let pad_len = if self.buf_len < 56 { 56 - self.buf_len } else { 120 - self.buf_len };
        self.update(&pad[..pad_len]);
        self.update(&bits.to_le_bytes());
        let mut out = [0u8; 16];
        for (o, w) in out.chunks_mut(4).zip(self.state) {
            o.copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 16] {
        let mut h = Md4::new();
        h.update(data);
        h.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    #[test]
    fn rfc1320_vectors() {
        for (input, want) in [
            ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
            ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
            ("message digest", "d9130a8164549fe818874806e1c7014b"),
            ("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
            ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"),
            ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536"),
        ] {
            assert_eq!(hex(&Md4::digest(input.as_bytes())), want, "{input:?}");
        }
        // every split point gives the same digest
        let msg: Vec<u8> = (0..130u8).collect();
        let whole = Md4::digest(&msg);
        for cut in 0..msg.len() {
            let mut h = Md4::new();
            h.update(&msg[..cut]);
            h.update(&msg[cut..]);
            assert_eq!(h.finish(), whole);
        }
    }

    #[test]
    fn nt_hash() {
        // NTOWFv1("Password") = MD4(UTF-16LE("Password")), MS-NLMP section 4.2.2.1.2
        let pw: Vec<u8> = "Password".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(hex(&Md4::digest(&pw)), "a4f49c406510bdcab6824ee7c30fd852");
    }
}
