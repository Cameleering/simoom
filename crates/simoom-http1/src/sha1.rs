//! SHA-1 (FIPS 180-4), only for `Sec-WebSocket-Accept`, where RFC 6455 requires it. Not for
//! any security purpose.

pub(crate) fn sha1(parts: &[&[u8]]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut block = [0u8; 64];
    let mut fill = 0;
    let bits = (total as u64) * 8;
    let pad_len = if total % 64 < 56 { 56 - total % 64 } else { 120 - total % 64 };
    let mut pad = [0u8; 72];
    pad[0] = 0x80;
    pad[pad_len..pad_len + 8].copy_from_slice(&bits.to_be_bytes());
    let tail = &pad[..pad_len + 8];
    for part in parts.iter().copied().chain(std::iter::once(tail)) {
        for &b in part {
            block[fill] = b;
            fill += 1;
            if fill == 64 {
                compress(&mut h, &block);
                fill = 0;
            }
        }
    }
    let mut out = [0u8; 20];
    for (o, v) in out.chunks_exact_mut(4).zip(h) {
        o.copy_from_slice(&v.to_be_bytes());
    }
    out
}

fn compress(h: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for (i, c) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *h;
    for (i, &wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
            20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
            _ => (b ^ c ^ d, 0xCA62_C1D6),
        };
        let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
        *x = x.wrapping_add(y);
    }
}

#[cfg(test)]
mod tests {
    use super::sha1;

    fn hex(d: [u8; 20]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn fips_vectors() {
        assert_eq!(hex(sha1(&[b""])), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(sha1(&[b"abc"])), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hex(sha1(&[b"abcdbcdecdefdefgefghfghighij", b"hijkijkljklmklmnlmnomnopnopq"])),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        let million = vec![b'a'; 1_000_000];
        assert_eq!(hex(sha1(&[&million])), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
        // Lengths around the padding boundary.
        for n in 54..=66 {
            let v = vec![b'x'; n];
            assert_eq!(sha1(&[&v]), sha1(&[&v[..n / 2], &v[n / 2..]]));
        }
    }
}
