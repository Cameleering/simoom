//! TLS 1.3 record protection (RFC 8446 section 5.2), in place.

use super::keyschedule::traffic_key_iv;
use super::{alert, AeadAlg, CipherSuite, Error, Result};
#[cfg(feature = "chacha20")]
use crate::crypto::chacha::ChaCha20Poly1305;
use crate::crypto::gcm::AesGcm;

pub(crate) const MAX_PLAINTEXT: usize = 16384;
/// Ciphertext limit: plaintext + content type + padding allowance + tag (RFC 8446 5.2).
pub(crate) const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;
pub(crate) const TAG: usize = 16;

/// An AEAD instance.
#[derive(Clone)]
#[allow(clippy::large_enum_variant)] // one per connection or key; boxing would add an indirection on the hot path
pub(crate) enum Aead {
    Gcm(AesGcm),
    #[cfg(feature = "chacha20")]
    ChaCha(ChaCha20Poly1305),
}

impl Aead {
    pub fn new(alg: AeadAlg, key: &[u8]) -> Aead {
        match alg {
            AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm => Aead::Gcm(AesGcm::new(key)),
            #[cfg(feature = "chacha20")]
            AeadAlg::Chacha20Poly1305 => Aead::ChaCha(ChaCha20Poly1305::new(key.try_into().expect("32-byte key"))),
        }
    }
    #[inline]
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        match self {
            Aead::Gcm(a) => a.seal(nonce, aad, data),
            #[cfg(feature = "chacha20")]
            Aead::ChaCha(a) => a.seal(nonce, aad, data),
        }
    }
    #[inline]
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8]) -> bool {
        match self {
            Aead::Gcm(a) => a.open(nonce, aad, data, tag),
            #[cfg(feature = "chacha20")]
            Aead::ChaCha(a) => a.open(nonce, aad, data, tag),
        }
    }
}

/// The per-record nonce: the IV XORed with the 64-bit sequence number.
#[inline]
pub(crate) fn nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut n = *iv;
    for (b, s) in n[4..].iter_mut().zip(seq.to_be_bytes()) {
        *b ^= s;
    }
    n
}

/// Protection state for one direction.
pub(crate) struct RecordCipher {
    aead: Aead,
    iv: [u8; 12],
    pub seq: u64,
}

impl RecordCipher {
    pub fn new(suite: CipherSuite, secret: &[u8]) -> RecordCipher {
        let (key, iv) = traffic_key_iv(suite, secret);
        RecordCipher { aead: Aead::new(suite.aead(), &key), iv, seq: 0 }
    }

    /// Appends one protected record carrying `payload` of content type `typ` to `out`.
    pub fn seal_record(&mut self, typ: u8, payload: &[u8], out: &mut Vec<u8>) -> Result<()> {
        debug_assert!(payload.len() <= MAX_PLAINTEXT);
        if self.seq == u64::MAX {
            return Err(Error::proto(alert::INTERNAL_ERROR, "sequence number exhausted"));
        }
        let len = payload.len() + 1 + TAG;
        let start = out.len();
        out.reserve(5 + len);
        out.extend_from_slice(&[super::content::APPLICATION_DATA, 3, 3, (len >> 8) as u8, len as u8]);
        out.extend_from_slice(payload);
        out.push(typ);
        let n = nonce(&self.iv, self.seq);
        let (hdr, body) = out[start..].split_at_mut(5);
        let tag = self.aead.seal(&n, hdr, body);
        out.extend_from_slice(&tag);
        self.seq += 1;
        Ok(())
    }

    /// Decrypts a record body in place (`header` is the 5-byte record header). Returns the inner
    /// content type and the plaintext length (the plaintext starts at `body[0]`).
    pub fn open_record(&mut self, header: &[u8; 5], body: &mut [u8]) -> Result<(u8, usize)> {
        if body.len() < TAG + 1 {
            return Err(Error::proto(alert::BAD_RECORD_MAC, "record too short"));
        }
        if self.seq == u64::MAX {
            return Err(Error::proto(alert::INTERNAL_ERROR, "sequence number exhausted"));
        }
        let n = nonce(&self.iv, self.seq);
        let (ct, tag) = body.split_at_mut(body.len() - TAG);
        if !self.aead.open(&n, header, ct, tag) {
            return Err(Error::proto(alert::BAD_RECORD_MAC, "record authentication failed"));
        }
        self.seq += 1;
        // strip zero padding, then the content type
        let mut end = ct.len();
        while end > 0 && ct[end - 1] == 0 {
            end -= 1;
        }
        if end == 0 {
            return Err(Error::proto(alert::UNEXPECTED_MESSAGE, "record without content type"));
        }
        let typ = ct[end - 1];
        if end - 1 > MAX_PLAINTEXT {
            return Err(Error::proto(alert::RECORD_OVERFLOW, "plaintext too long"));
        }
        Ok((typ, end - 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::unhex;

    #[test]
    fn roundtrip_padding_and_tamper() {
        let secret = unhex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
        for suite in CipherSuite::ALL {
            let mut tx = RecordCipher::new(suite, &secret[..suite.hash().output_len().min(32)]);
            let mut rx = RecordCipher::new(suite, &secret[..suite.hash().output_len().min(32)]);
            let mut out = Vec::new();
            tx.seal_record(super::super::content::HANDSHAKE, b"hello", &mut out).unwrap();
            tx.seal_record(super::super::content::APPLICATION_DATA, b"", &mut out).unwrap();
            assert_eq!(&out[..3], &[23, 3, 3]);
            let first = 5 + 5 + 1 + 16;
            let hdr: [u8; 5] = out[..5].try_into().unwrap();
            let (t, n) = rx.open_record(&hdr, &mut out[5..first]).unwrap();
            assert_eq!((t, &out[5..5 + n]), (22, &b"hello"[..]));
            let hdr: [u8; 5] = out[first..first + 5].try_into().unwrap();
            let mut body = out[first + 5..].to_vec();
            body[0] ^= 1;
            assert!(rx.open_record(&hdr, &mut body).is_err());
        }
    }
}
