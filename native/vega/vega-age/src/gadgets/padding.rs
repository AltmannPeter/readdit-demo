//! SHA-256 padding checked in the rules, for a message whose padded blocks fill its region exactly
//! (FIPS 180-4, 5.1.1): the message's private length L, the byte 0x80 at L, zeros after it, and
//! the length field 8L in the last eight bytes.
//!
//! The step instances check the compressions of the region's blocks from the initial value, so
//! the state after its last block is the SHA-256 digest of its first L bytes exactly when these
//! rules hold. A reader of the message then bounds every window by L
//! ([`super::window::Message::of_length`]), so no read reaches the padding, and no byte after the
//! message can pass for one of it.
//!
//! The region holds B ≥ 2 blocks, so L lies from 64 (B − 2) + 56 to 64 (B − 2) + 119: the padding
//! byte sits at position p = L − 64 (B − 2), from 56 to 119, of the last two blocks. The rules:
//!
//! 1. the bytes of the last two blocks from position 48 on (the second last block's last chunk
//!    and the last block's four), each split into bits (128 per chunk) and packed by eight;
//! 2. a one-hot e over the positions 56 to 119, whose index is p − 56, and its thermometer
//!    g_r = Σ_{j ≤ r} e_j, which is one from p on;
//! 3. at each position r from 56 to 119, t_r · g_r = 0x80 · e_r: the byte at p is 0x80 and every
//!    later one before the length field is zero (the bytes before p are the message's, free);
//! 4. the last eight bytes, a big-endian integer, equal 8 L, with L = 64 (B − 2) + 56 + index(e).
//!
//! 64 + 1 rules for the one-hot, 640 + 5 for the bytes, 64 products and one rule for the length.

use bellpepper_core::{ConstraintSystem, SynthesisError};
use vega_prover::provider::pt256::t256;

use super::bits::{bits, bytes, pack_bytes};
use super::lc::{Lc, equal, product};
use super::select::OneHot;
use crate::table::{CHUNKS_PER_BLOCK, Cells, Region};

/// The positions, counted from the second last block's first byte, where the padding byte can sit.
const FIRST: usize = 56;
const LAST: usize = 119;

/// The lengths of a message whose padding fills `blocks` blocks exactly.
pub fn lengths(blocks: usize) -> std::ops::RangeInclusive<usize> {
  assert!(blocks >= 2, "a padded region of two blocks or more");
  64 * (blocks - 2) + FIRST..=64 * (blocks - 2) + LAST
}

/// The rules above for the message in `region` (of two blocks or more), of the private length
/// `len`. Returns the length, a weighted sum of the one-hot's bits.
pub fn padded<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  cells: &Cells,
  region: Region,
  len: Option<usize>,
) -> Result<Lc, SynthesisError> {
  assert!(region.blocks >= 2, "a padded region of two blocks or more");
  let base = 64 * (region.blocks - 2);
  if len.is_some_and(|l| !lengths(region.blocks).contains(&l)) {
    return Err(SynthesisError::Unsatisfiable);
  }

  // 1. The bytes from position 48 of the second last block: its last chunk, then the last
  // block's four.
  let second_last = region.first + region.blocks - 2;
  let chunks = std::iter::once(CHUNKS_PER_BLOCK * second_last + 3)
    .chain((0..CHUNKS_PER_BLOCK).map(|c| CHUNKS_PER_BLOCK * (second_last + 1) + c));
  let mut tail = Vec::with_capacity(80);
  for (i, c) in chunks.enumerate() {
    let chunk_bits = bits(cs.namespace(|| format!("tail chunk {i} bits")), &cells.chunk(c), 128)?;
    tail.extend(bytes(&chunk_bits));
  }
  // tail[k] is the byte at position 48 + k.
  let byte = |r: usize| &tail[r - 48];

  // 2. The padding byte's position.
  let index = len.map(|l| l - base - FIRST);
  let e = OneHot::alloc(cs.namespace(|| "padding position"), LAST - FIRST + 1, index)?;

  // 3. The byte 0x80 at p, zeros after it.
  let mut from_p = Lc::zero();
  for r in FIRST..=LAST {
    let at = e.within(r - FIRST..r - FIRST + 1);
    from_p = from_p + &at;
    let expected = at.scale(t256::Scalar::from(0x80));
    product(cs.namespace(|| format!("padding byte {r}")), byte(r), &from_p, &expected);
  }

  // 4. The length field.
  let length = e.index() + &Lc::small((base + FIRST) as u64);
  let field: Vec<Lc> = (120..128).map(|r| byte(r).clone()).collect();
  equal(cs.namespace(|| "length field"), &pack_bytes(&field), &length.scale(t256::Scalar::from(8)));
  Ok(length)
}
