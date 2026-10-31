//! SHA-256 (FIPS 180-4) with the intermediate values the hash circuit takes as witness: per block,
//! the chaining value after it, the message schedule's words W_16 to W_63, and each round's new e
//! and new a.

pub const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// One block's compression and its trace.
pub struct BlockTrace {
    /// The chaining value after the block.
    pub out: [u32; 8],
    /// W_16 to W_63.
    pub schedule: [u32; 48],
    /// Each round's new e (rounds 0 to 63).
    pub e: [u32; 64],
    /// Each round's new a.
    pub a: [u32; 64],
}

pub fn compress(state: &[u32; 8], block: &[u8]) -> BlockTrace {
    let mut w = [0u32; 64];
    for (i, c) in block.chunks_exact(4).enumerate().take(16) {
        w[i] = u32::from_be_bytes(c.try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    let mut es = [0u32; 64];
    let mut as_ = [0u32; 64];
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
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
        es[i] = e;
        as_[i] = a;
    }
    let add = [a, b, c, d, e, f, g, h];
    let mut out = [0u32; 8];
    for i in 0..8 {
        out[i] = state[i].wrapping_add(add[i]);
    }
    let mut schedule = [0u32; 48];
    schedule.copy_from_slice(&w[16..]);
    BlockTrace {
        out,
        schedule,
        e: es,
        a: as_,
    }
}

/// The message padded (FIPS 180-4, 5.1.1).
pub fn pad(m: &[u8]) -> Vec<u8> {
    let mut p = m.to_vec();
    p.push(0x80);
    while p.len() % 64 != 56 {
        p.push(0);
    }
    p.extend_from_slice(&((m.len() as u64) * 8).to_be_bytes());
    p
}

/// The chaining value's 32 bytes (each word big-endian).
pub fn state_bytes(s: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, w) in s.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

/// The padded message's blocks compressed from the initial value, each block's trace.
pub fn hash_trace(m: &[u8]) -> (Vec<u8>, Vec<BlockTrace>) {
    let p = pad(m);
    let mut st = IV;
    let mut traces = Vec::with_capacity(p.len() / 64);
    for blk in p.chunks_exact(64) {
        let t = compress(&st, blk);
        st = t.out;
        traces.push(t);
    }
    (p, traces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    #[test]
    fn matches_sha2() {
        for n in [0usize, 26, 55, 56, 64, 119, 423] {
            let m: Vec<u8> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
            let (_, t) = hash_trace(&m);
            assert_eq!(state_bytes(&t.last().unwrap().out), Sha256::digest(&m).as_slice());
        }
    }
}
