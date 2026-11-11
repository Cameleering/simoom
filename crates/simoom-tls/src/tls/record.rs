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
    /// TLS 1.2 record format: 0 = TLS 1.3, 1 = AES-GCM with an explicit nonce, 2 =
    /// ChaCha20-Poly1305 (RFC 7905, nonce = IV xor sequence number).
    #[cfg(feature = "tls12")]
    v12: u8,
}

impl RecordCipher {
    pub fn new(suite: CipherSuite, secret: &[u8]) -> RecordCipher {
        let (key, iv) = traffic_key_iv(suite, secret);
        RecordCipher {
            aead: Aead::new(suite.aead(), &key),
            iv,
            seq: 0,
            #[cfg(feature = "tls12")]
            v12: 0,
        }
    }

    /// A TLS 1.2 record cipher (RFC 5288 AES-GCM, RFC 7905 ChaCha20-Poly1305) from the key
    /// block's write key and IV (4 bytes of salt for GCM, 12 for ChaCha20).
    #[cfg(feature = "tls12")]
    pub fn tls12(alg: AeadAlg, key: &[u8], iv: &[u8]) -> RecordCipher {
        let mut n = [0u8; 12];
        n[..iv.len()].copy_from_slice(iv);
        #[cfg(feature = "chacha20")]
        let v12 = if alg == AeadAlg::Chacha20Poly1305 { 2 } else { 1 };
        #[cfg(not(feature = "chacha20"))]
        let v12 = 1;
        RecordCipher { aead: Aead::new(alg, key), iv: n, seq: 0, v12 }
    }


    #[cfg(feature = "tls12")]
    fn aad12(&self, typ: u8, len: usize) -> [u8; 13] {
        let mut a = [0u8; 13];
        a[..8].copy_from_slice(&self.seq.to_be_bytes());
        a[8] = typ;
        a[9] = 3;
        a[10] = 3;
        a[11..].copy_from_slice(&(len as u16).to_be_bytes());
        a
    }

    /// TLS 1.2: appends one protected record of type `typ` (RFC 5246 section 6.2.3.3).
    #[cfg(feature = "tls12")]
    fn seal_record12(&mut self, typ: u8, payload: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let explicit = if self.v12 == 1 { 8 } else { 0 };
        let len = explicit + payload.len() + TAG;
        out.reserve(5 + len);
        out.extend_from_slice(&[typ, 3, 3, (len >> 8) as u8, len as u8]);
        if explicit > 0 {
            out.extend_from_slice(&self.seq.to_be_bytes());
        }
        let start = out.len();
        out.extend_from_slice(payload);
        let aad = self.aad12(typ, payload.len());
        let n = nonce(&self.iv, self.seq);
        let tag = self.aead.seal(&n, &aad, &mut out[start..]);
        out.extend_from_slice(&tag);
        self.seq += 1;
        Ok(())
    }

    /// TLS 1.2: decrypts a record body in place. Returns the content type (the record
    /// header's), the offset of the plaintext in `body` and its length.
    #[cfg(feature = "tls12")]
    pub fn open_record12(&mut self, header: &[u8; 5], body: &mut [u8]) -> Result<(u8, usize, usize)> {
        let explicit = if self.v12 == 1 { 8 } else { 0 };
        if body.len() < explicit + TAG {
            return Err(Error::proto(alert::BAD_RECORD_MAC, "record too short"));
        }
        if self.seq == u64::MAX {
            return Err(Error::proto(alert::INTERNAL_ERROR, "sequence number exhausted"));
        }
        let n = if explicit > 0 {
            let mut n = self.iv;
            n[4..].copy_from_slice(&body[..8]);
            n
        } else {
            nonce(&self.iv, self.seq)
        };
        let ct_len = body.len() - explicit - TAG;
        if ct_len > MAX_PLAINTEXT {
            return Err(Error::proto(alert::RECORD_OVERFLOW, "plaintext too long"));
        }
        let aad = self.aad12(header[0], ct_len);
        let (ct, tag) = body[explicit..].split_at_mut(ct_len);
        if !self.aead.open(&n, &aad, ct, tag) {
            return Err(Error::proto(alert::BAD_RECORD_MAC, "record authentication failed"));
        }
        self.seq += 1;
        Ok((header[0], explicit, ct_len))
    }

    /// Appends one protected record carrying `payload` of content type `typ` to `out`.
    pub fn seal_record(&mut self, typ: u8, payload: &[u8], out: &mut Vec<u8>) -> Result<()> {
        debug_assert!(payload.len() <= MAX_PLAINTEXT);
        if self.seq == u64::MAX {
            return Err(Error::proto(alert::INTERNAL_ERROR, "sequence number exhausted"));
        }
        #[cfg(feature = "tls12")]
        if self.v12 != 0 {
            return self.seal_record12(typ, payload, out);
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

    /// Whether this cipher uses the TLS 1.2 record format.
    #[inline]
    pub fn is_tls12(&self) -> bool {
        #[cfg(feature = "tls12")]
        return self.v12 != 0;
        #[cfg(not(feature = "tls12"))]
        false
    }

    /// Decrypts a record of either format: (content type, plaintext offset in `body`, length).
    #[inline]
    pub fn open_any(&mut self, header: &[u8; 5], body: &mut [u8]) -> Result<(u8, usize, usize)> {
        #[cfg(feature = "tls12")]
        if self.v12 != 0 {
            return self.open_record12(header, body);
        }
        self.open_record(header, body).map(|(t, n)| (t, 0, n))
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
