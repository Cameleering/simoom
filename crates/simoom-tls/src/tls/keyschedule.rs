//! The TLS 1.3 key schedule (RFC 8446 section 7).

use super::{codec, hs, CipherSuite};
use crate::crypto::sha2::{HashAlg, Output};

/// HKDF-Expand-Label with the given label prefix ("tls13 " for TLS, the same for QUIC).
#[inline(never)]
pub(crate) fn expand_label(h: HashAlg, secret: &[u8], label: &[u8], context: &[u8], out: &mut [u8]) {
    let mut info = Vec::with_capacity(4 + 6 + label.len() + context.len());
    codec::put_u16(&mut info, out.len() as u16);
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    codec::put_vec8(&mut info, context);
    h.hkdf_expand(secret, &[&info], out);
}

#[inline(never)]
pub(crate) fn expand_label_vec(h: HashAlg, secret: &[u8], label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    expand_label(h, secret, label, context, &mut out);
    out
}

#[inline(never)]
pub(crate) fn derive_secret(h: HashAlg, secret: &[u8], label: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    expand_label_vec(h, secret, label, transcript_hash, h.output_len())
}

/// The secrets of one handshake after the (EC)DHE exchange.
pub(crate) struct Schedule {
    pub h: HashAlg,
    pub client_hs: Vec<u8>,
    pub server_hs: Vec<u8>,
    master: Vec<u8>,
}

impl Drop for Schedule {
    fn drop(&mut self) {
        crate::util::zeroize(&mut self.client_hs);
        crate::util::zeroize(&mut self.server_hs);
        crate::util::zeroize(&mut self.master);
    }
}

impl Schedule {
    /// From the optional resumption PSK, the shared secret and the hash of ClientHello..ServerHello.
    pub fn new(h: HashAlg, psk: Option<&[u8]>, shared: &[u8], hello_hash: &[u8]) -> Schedule {
        let zeros = [0u8; 64];
        let zeros = &zeros[..h.output_len()];
        let early = h.hkdf_extract(zeros, psk.unwrap_or(zeros));
        let empty = h.hash(&[]);
        let derived = derive_secret(h, &early, b"derived", &empty);
        let handshake = h.hkdf_extract(&derived, shared);
        let client_hs = derive_secret(h, &handshake, b"c hs traffic", hello_hash);
        let server_hs = derive_secret(h, &handshake, b"s hs traffic", hello_hash);
        let derived2 = derive_secret(h, &handshake, b"derived", &empty);
        let master = h.hkdf_extract(&derived2, zeros).to_vec();
        Schedule { h, client_hs, server_hs, master }
    }

    /// (client, server) application traffic secrets from the hash through server Finished.
    pub fn app_secrets(&self, hash: &[u8]) -> (Vec<u8>, Vec<u8>) {
        (derive_secret(self.h, &self.master, b"c ap traffic", hash), derive_secret(self.h, &self.master, b"s ap traffic", hash))
    }

    /// resumption_master_secret from the hash through client Finished.
    pub fn resumption_master(&self, hash: &[u8]) -> Vec<u8> {
        derive_secret(self.h, &self.master, b"res master", hash)
    }

    /// exporter_master_secret from the hash through server Finished.
    pub fn exporter_master(&self, hash: &[u8]) -> Vec<u8> {
        derive_secret(self.h, &self.master, b"exp master", hash)
    }
}

/// The Finished verify_data for `base_key` (a handshake traffic secret or binder key).
pub(crate) fn finished_mac(h: HashAlg, base_key: &[u8], hash: &[u8]) -> Output {
    let fk = expand_label_vec(h, base_key, b"finished", &[], h.output_len());
    h.hmac(&fk, &[hash])
}

/// A PSK binder over the hash of the truncated ClientHello transcript.
pub(crate) fn psk_binder(h: HashAlg, psk: &[u8], transcript_hash: &[u8]) -> Output {
    let zeros = [0u8; 64];
    let early = h.hkdf_extract(&zeros[..h.output_len()], psk);
    let binder_key = derive_secret(h, &early, b"res binder", &h.hash(&[]));
    finished_mac(h, &binder_key, transcript_hash)
}

/// The PSK of a NewSessionTicket.
pub(crate) fn ticket_psk(h: HashAlg, resumption_master: &[u8], nonce: &[u8]) -> Vec<u8> {
    expand_label_vec(h, resumption_master, b"resumption", nonce, h.output_len())
}

/// The next application traffic secret (KeyUpdate).
pub(crate) fn next_traffic_secret(h: HashAlg, secret: &[u8]) -> Vec<u8> {
    expand_label_vec(h, secret, b"traffic upd", &[], h.output_len())
}

/// (key, iv) of a traffic secret.
pub(crate) fn traffic_key_iv(suite: CipherSuite, secret: &[u8]) -> (Vec<u8>, [u8; 12]) {
    let h = suite.hash();
    let key = expand_label_vec(h, secret, b"key", &[], suite.aead().key_len());
    let mut iv = [0u8; 12];
    expand_label(h, secret, b"iv", &[], &mut iv);
    (key, iv)
}

/// The synthetic `message_hash` message that replaces ClientHello1 after a HelloRetryRequest.
pub(crate) fn message_hash(h: HashAlg, ch1: &[u8]) -> Vec<u8> {
    codec::handshake_msg(hs::MESSAGE_HASH, &h.hash(ch1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex};

    #[test]
    fn rfc8448_simple_1rtt() {
        let shared = unhex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        let ch = unhex("010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001");
        let sh = unhex("020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304");
        let mut t = ch.clone();
        t.extend_from_slice(&sh);
        let h = HashAlg::Sha256;
        let s = Schedule::new(h, None, &shared, &h.hash(&t));
        assert_eq!(hex(&s.client_hs), "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
        assert_eq!(hex(&s.server_hs), "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
        let (key, iv) = traffic_key_iv(CipherSuite::Aes128GcmSha256, &s.server_hs);
        assert_eq!(hex(&key), "3fce516009c21727d0f2e4e86ee403bc");
        assert_eq!(hex(&iv), "5d313eb2671276ee13000b30");
    }

    #[test]
    fn acvp_tls13_kdf_with_psk() {
        let psk = unhex("56288B726C73829F7A3E47B103837C8139ACF552E7530C7A710B35ED41191698");
        let dhe = unhex("EFFE9EC26AA29FD750DFA6A10B944D74071595B27EE88887D5E11C84590B5CC3");
        let mut transcript = unhex("E9137679E582BA7C1DB41CF725F86C6D09C8C05F297BAD9A65B552EAF524FDE4");
        transcript.extend(unhex("23ECCFD030790748C8F8D8A656FD98D717F1B62AF3712F97211D2070B499F98A"));
        let h = HashAlg::Sha256;
        let s = Schedule::new(h, Some(&psk), &dhe, &h.hash(&transcript));
        assert_eq!(hex(&s.client_hs), "b32306c3ce9932c460a1fe6c0f060593974842036b96fa45049b7352e71c2ad2");
        assert_eq!(hex(&s.server_hs), "22787f8ca269d34bc549ac8ba19f2040938a3aa370d7cc9d60f720882b88d01b");
        transcript.extend(unhex("C750EDA6696CD101B142BD79E00E6AC8C5F2C0ABC78DD64F4D991326659E9299"));
        let (c, sv) = s.app_secrets(&h.hash(&transcript));
        assert_eq!(hex(&c), "47d7ea08397b5871154b0fe85584bcc30a87c69e84d69b56007c5b21f76493ba");
        assert_eq!(hex(&sv), "efbdb0c873c0480da57307083839a8984be25b9a8545e4fca029940fe2800565");
    }
}
