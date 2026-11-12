//! P2 (feature `aes-rng`, off by default; for benchmarks): a random engine that draws the
//! prover's randomness from AES-256 in counter mode instead of one OS call per draw. Google's
//! `SecureRandomEngine` calls the OS CSPRNG for every field element, nonce and challenge (about
//! 25,700 calls per proof); this engine calls it once, for its key.
//!
//! - The 32-byte key comes from the OS CSPRNG (`getrandom`) when the engine is made. Make one
//!   engine per proof ([`AesCtrRng::new`] before `prebuild`, the same engine into
//!   `prove_prebuilt`) and drop it after: a key is never reused, and nothing is derived from the
//!   witness or the request.
//! - The keystream is AES-256 of a 128-bit big-endian counter starting at zero (CTR, NIST SP
//!   800-38A), 64 blocks at a time.
//! - The key is zeroised once the key schedule is built; the key schedule (the `aes` crate's
//!   `zeroize` feature), the unused keystream and the counter are zeroised when the engine is
//!   dropped.

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes256;
use runtime_random::RandomEngine;
use zeroize::{Zeroize, Zeroizing};

const BLOCKS: usize = 64;

/// AES-256-CTR keyed from the OS CSPRNG: one per proof. Not `Clone`: a copy would repeat the
/// keystream.
pub struct AesCtrRng {
    cipher: Aes256,
    counter: u128,
    buf: [u8; 16 * BLOCKS],
    pos: usize,
}

impl AesCtrRng {
    /// A fresh engine with a new key from the OS CSPRNG. Panics when the OS has no CSPRNG to
    /// give, as Google's engine does.
    pub fn new() -> AesCtrRng {
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(key.as_mut()).expect("Failed to generate secure random bytes from OS CSPRNG");
        AesCtrRng::with_key(&key, 0)
    }

    fn with_key(key: &[u8; 32], counter: u128) -> AesCtrRng {
        AesCtrRng { cipher: Aes256::new(GenericArray::from_slice(key)), counter, buf: [0; 16 * BLOCKS], pos: 16 * BLOCKS }
    }

    /// For the known-answer test only: SP 800-38A's key and initial counter block.
    #[doc(hidden)]
    pub fn for_test(key: &[u8; 32], counter_block: [u8; 16]) -> AesCtrRng {
        AesCtrRng::with_key(key, u128::from_be_bytes(counter_block))
    }

    fn refill(&mut self) {
        let mut blocks = [GenericArray::default(); BLOCKS];
        for b in blocks.iter_mut() {
            b.copy_from_slice(&self.counter.to_be_bytes());
            self.counter = self.counter.wrapping_add(1);
        }
        self.cipher.encrypt_blocks(&mut blocks);
        for (k, b) in blocks.iter_mut().enumerate() {
            self.buf[16 * k..16 * k + 16].copy_from_slice(b);
            b.zeroize();
        }
        self.pos = 0;
    }
}

impl Default for AesCtrRng {
    fn default() -> AesCtrRng {
        AesCtrRng::new()
    }
}

impl RandomEngine for AesCtrRng {
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            if self.pos == self.buf.len() {
                self.refill();
            }
            let take = (len - out.len()).min(self.buf.len() - self.pos);
            out.extend_from_slice(&self.buf[self.pos..self.pos + take]);
            // A drawn byte is not kept.
            self.buf[self.pos..self.pos + take].zeroize();
            self.pos += take;
        }
        out
    }
}

impl Drop for AesCtrRng {
    fn drop(&mut self) {
        self.buf.zeroize();
        self.counter.zeroize();
    }
}

impl std::fmt::Debug for AesCtrRng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AesCtrRng(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    /// NIST SP 800-38A, F.5.5 CTR-AES256.Encrypt: the keystream is the ciphertext XOR the
    /// plaintext, block by block.
    #[test]
    fn sp800_38a_f55() {
        let key: [u8; 32] = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").try_into().unwrap();
        let ctr: [u8; 16] = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").try_into().unwrap();
        let pt = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
        let ct = hex("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6");
        let ks: Vec<u8> = pt.iter().zip(&ct).map(|(p, c)| p ^ c).collect();
        // Drawn in uneven pieces, across the buffer's refills too.
        let mut rng = AesCtrRng::for_test(&key, ctr);
        let mut got = rng.bytes(5);
        got.extend(rng.bytes(16));
        got.extend(rng.bytes(43));
        assert_eq!(got, ks);
        let mut long = AesCtrRng::for_test(&key, ctr);
        let all = long.bytes(16 * BLOCKS * 2 + 7);
        assert_eq!(&all[..64], &ks[..]);
        let mut again = AesCtrRng::for_test(&key, ctr);
        let mut pieces = Vec::new();
        while pieces.len() < all.len() {
            pieces.extend(again.bytes(33.min(all.len() - pieces.len())));
        }
        assert_eq!(pieces, all);
    }

    #[test]
    fn a_new_engine_has_a_new_key() {
        let (a, b) = (AesCtrRng::new().bytes(64), AesCtrRng::new().bytes(64));
        assert_ne!(a, b);
        assert_eq!(format!("{:?}", AesCtrRng::new()), "AesCtrRng(..)");
    }
}
