//! The values of bellpepper's SHA-256 compression, computed natively.
//!
//! The step circuit checks each compression with bellpepper's `sha256_compression_function`
//! (bellpepper 0.4), whose synthesis builds a weighted sum for every bit it allocates. Here
//! [`compression`] computes the same values with the native SHA-256 rounds, in the gadget's order,
//! for a block and a state whose bits are all allocated, as the step's are. The gadget then
//! allocates:
//! - for each word w[16..64] of the schedule: the bits of the two XORs of σ0 (32, then 29: the
//!   shift's three top bits are constant zeros, which a XOR passes through), of σ1 (32, then 22),
//!   and the 34 bits of the sum of the four words;
//! - in each round: the 35 bits of the sum that gives e (from the second round on), the bits of
//!   Σ1's two XORs (32 each) and of Ch (32), the 35 bits of the sum that gives a (from the second
//!   round on), the bits of Σ0's two XORs (32 each), and for each bit of Maj its value and the
//!   AND of b and c (64);
//! - for the new state: the bits of each sum, 35 for a and e (whose deferred sums take the old
//!   state's word as one more operand) and 33 for the others.
//!
//! Each sum of n words allocates the bit length of n · (2^32 − 1) bits of its integer, least
//! significant first, and each XOR, Ch and Maj its bits, least significant first.

use super::values::Values;

/// The round constants of SHA-256 (FIPS 180-4, clause 4.2.2).
const ROUND_CONSTANTS: [u32; 64] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Pushes the values bellpepper's `sha256_compression_function` allocates when it compresses
/// `block` (its sixteen big-endian words) from `state`, and returns the state after it.
pub fn compression(values: &mut Values, block: &[u32; 16], state: &[u32; 8]) -> [u32; 8] {
  let mut w = [0u32; 64];
  w[..16].copy_from_slice(block);
  for i in 16..64 {
    let x = w[i - 15];
    let first = x.rotate_right(7) ^ x.rotate_right(18);
    values.low_bits(u64::from(first), 32);
    let s0 = first ^ (x >> 3);
    values.low_bits(u64::from(s0), 29);
    let y = w[i - 2];
    let first = y.rotate_right(17) ^ y.rotate_right(19);
    values.low_bits(u64::from(first), 32);
    let s1 = first ^ (y >> 10);
    values.low_bits(u64::from(s1), 22);
    let sum = u64::from(w[i - 16]) + u64::from(s0) + u64::from(w[i - 7]) + u64::from(s1);
    values.low_bits(sum, 34);
    w[i] = sum as u32;
  }

  let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
  // The gadget defers the sums that give e and a, and allocates them where the next round, or
  // the new state, reads them: e = d + temp1 and a = temp1 + temp2.
  let mut deferred: Option<(u64, u64)> = None;
  for i in 0..64 {
    if let Some((e_sum, _)) = deferred {
      values.low_bits(e_sum, 35);
      e = e_sum as u32;
    }
    let first = e.rotate_right(6) ^ e.rotate_right(11);
    values.low_bits(u64::from(first), 32);
    let s1 = first ^ e.rotate_right(25);
    values.low_bits(u64::from(s1), 32);
    let ch = (e & f) ^ (!e & g);
    values.low_bits(u64::from(ch), 32);
    let temp1 = u64::from(h)
      + u64::from(s1)
      + u64::from(ch)
      + u64::from(ROUND_CONSTANTS[i])
      + u64::from(w[i]);
    if let Some((_, a_sum)) = deferred {
      values.low_bits(a_sum, 35);
      a = a_sum as u32;
    }
    let first = a.rotate_right(2) ^ a.rotate_right(13);
    values.low_bits(u64::from(first), 32);
    let s0 = first ^ a.rotate_right(22);
    values.low_bits(u64::from(s0), 32);
    let maj = (a & b) ^ (a & c) ^ (b & c);
    let bc = b & c;
    for k in 0..32 {
      values.bit((maj >> k) & 1 == 1);
      values.bit((bc >> k) & 1 == 1);
    }
    let temp2 = u64::from(s0) + u64::from(maj);
    h = g;
    g = f;
    f = e;
    let e_sum = u64::from(d) + temp1;
    d = c;
    c = b;
    b = a;
    deferred = Some((e_sum, temp1 + temp2));
  }
  let (e_sum, a_sum) = deferred.expect("64 rounds");

  let sums = [
    (a_sum + u64::from(state[0]), 35),
    (u64::from(state[1]) + u64::from(b), 33),
    (u64::from(state[2]) + u64::from(c), 33),
    (u64::from(state[3]) + u64::from(d), 33),
    (e_sum + u64::from(state[4]), 35),
    (u64::from(state[5]) + u64::from(f), 33),
    (u64::from(state[6]) + u64::from(g), 33),
    (u64::from(state[7]) + u64::from(h), 33),
  ];
  let mut after = [0u32; 8];
  for (word, (sum, n)) in after.iter_mut().zip(sums) {
    values.low_bits(sum, n);
    *word = sum as u32;
  }
  after
}
