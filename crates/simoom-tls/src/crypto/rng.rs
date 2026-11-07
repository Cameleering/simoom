//! Cryptographically secure random numbers: a ChaCha20 DRBG with fast key erasure, seeded and
//! periodically reseeded from the operating system (`simoom_sys::arch::os_random`).
//!
//! Each thread keeps its own generator, so there is no lock on the handshake path. After every
//! request the next 32 bytes of keystream replace the key, so a later compromise of the state
//! does not reveal earlier output. A failing OS source panics: weak randomness is never used.

use super::chacha::chacha20_block;
use std::cell::RefCell;

const RESEED_BYTES: u64 = 1 << 20;

struct Drbg {
    key: [u8; 32],
    counter: u64,
    generated: u64,
}

fn os_seed(out: &mut [u8; 32]) {
    assert!(simoom_sys::arch::os_random(out), "simoom-tls: the operating system random source failed");
}

impl Drbg {
    fn seeded() -> Drbg {
        let mut key = [0u8; 32];
        os_seed(&mut key);
        Drbg { key, counter: 0, generated: 0 }
    }

    fn block(&mut self) -> [u8; 64] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.counter.to_le_bytes());
        self.counter = self.counter.wrapping_add(1);
        chacha20_block(&self.key, 0, &nonce)
    }

    fn fill(&mut self, out: &mut [u8]) {
        if self.generated > RESEED_BYTES {
            let mut fresh = [0u8; 32];
            os_seed(&mut fresh);
            for (k, f) in self.key.iter_mut().zip(fresh) {
                *k ^= f;
            }
            self.generated = 0;
        }
        for chunk in out.chunks_mut(64) {
            let b = self.block();
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
        let b = self.block();
        self.key.copy_from_slice(&b[..32]);
        self.generated += out.len() as u64 + 64;
    }
}

thread_local! {
    static RNG: RefCell<Option<Drbg>> = const { RefCell::new(None) };
}

/// Fills `out` with random bytes.
pub fn fill(out: &mut [u8]) {
    RNG.with(|r| r.borrow_mut().get_or_insert_with(Drbg::seeded).fill(out));
}

/// `N` random bytes.
pub fn array<const N: usize>() -> [u8; N] {
    let mut a = [0u8; N];
    fill(&mut a);
    a
}

/// `n` random bytes.
pub fn bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    fill(&mut v);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outputs_differ_and_are_balanced() {
        assert_ne!(array::<32>(), array::<32>());
        let big = bytes(1 << 16);
        let ones: u32 = big.iter().map(|x| x.count_ones()).sum();
        let ratio = ones as f64 / (big.len() * 8) as f64;
        assert!((ratio - 0.5).abs() < 0.01, "bit ratio {ratio}");
    }

    #[test]
    fn deterministic_given_key_and_erases_it() {
        let mut d1 = Drbg { key: [7; 32], counter: 0, generated: 0 };
        let mut d2 = Drbg { key: [7; 32], counter: 0, generated: 0 };
        let (mut a, mut b) = ([0u8; 100], [0u8; 100]);
        d1.fill(&mut a);
        d2.fill(&mut b);
        assert_eq!(a, b);
        assert_ne!(d1.key, [7; 32]);
        d1.fill(&mut a);
        assert_ne!(a, b);
    }
}
