//! An AES-256-CTR random engine (feature `aes-ctr-rng`, for benchmarks; off by default).
//!
//! Google's `SecureRandomEngine` asks the operating system for every field element (about 25,000
//! calls a presentation); this engine asks once, for a 32-byte key, and expands it with AES-256 in
//! counter mode. Use a new engine for every presentation: a key reused for two presentations with
//! different witnesses would repeat their blinding and leak witness data. The proof format, the
//! verifier and the circuits are the same with either engine.

use aes::cipher::{BlockEncrypt, KeyInit};
use runtime_random::{RandomEngine, SecureRandomEngine};

/// AES-256-CTR keyed once from the operating system's CSPRNG.
pub struct AesCtrEngine {
    cipher: aes::Aes256,
    counter: u128,
    buf: [u8; 4096],
    pos: usize,
}

impl AesCtrEngine {
    /// A new engine with a fresh 32-byte key from the operating system.
    #[must_use]
    pub fn new() -> Self {
        let mut key = SecureRandomEngine::new().bytes(32);
        let cipher = aes::Aes256::new_from_slice(&key).expect("32-byte key");
        key.iter_mut().for_each(|b| *b = 0);
        Self { cipher, counter: 0, buf: [0u8; 4096], pos: 4096 }
    }

    fn refill(&mut self) {
        for chunk in self.buf.chunks_exact_mut(16) {
            chunk.copy_from_slice(&self.counter.to_le_bytes());
            self.counter += 1;
            self.cipher.encrypt_block(chunk.into());
        }
        self.pos = 0;
    }
}

impl Default for AesCtrEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RandomEngine for AesCtrEngine {
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            if self.pos == self.buf.len() {
                self.refill();
            }
            let n = (len - out.len()).min(self.buf.len() - self.pos);
            out.extend_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
        }
        out
    }
}

impl Drop for AesCtrEngine {
    fn drop(&mut self) {
        self.buf.iter_mut().for_each(|b| *b = 0);
    }
}
