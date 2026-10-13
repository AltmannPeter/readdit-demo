//! Reading the bytes of a signed message at a private offset.
//!
//! The core circuit reads a value, such as the birth date, from where the issuer wrote it. The
//! prover supplies the offset. The trusted issuer writes the constant bytes around each value,
//! such as a key name, only in that one place, so a window whose constant bytes match can only
//! sit there.

use bellpepper_core::{ConstraintSystem, SynthesisError};
use ff::Field;
use vega_prover::provider::pt256::t256;

use super::bits::{alloc_bits, bits, bytes, pack, range_check, small_bits};
use super::lc::{Lc, low_bytes, mux};
use super::select::{OneHot, select_values};
use super::values::Values;
use crate::table::{CHUNK_BYTES, CHUNKS_PER_BLOCK, Cells, OFFSET_BITS, Region};

/// The offset of the first occurrence of `pattern` in `bytes`. The prover uses it to find where
/// the issuer wrote a value.
pub fn find(bytes: &[u8], pattern: &[u8], what: &str) -> Result<usize, String> {
  bytes.windows(pattern.len()).position(|w| w == pattern).ok_or_else(|| format!("{what} not found"))
}

/// One message of the shared table, as a core circuit reads it.
pub struct Message<'a> {
  cells: &'a Cells<'a>,
  region: Region,
  last: OneHot,
}

/// Bytes read at an offset, and the offset as a sum of slots.
pub struct Window {
  pub bytes: Vec<Lc>,
  pub offset: Lc,
}

impl<'a> Message<'a> {
  /// Selects the message's last block, a private index within the region, and reads the state
  /// after it. That state is the message's SHA-256 digest, as two 128-bit halves.
  pub fn open<CS: ConstraintSystem<t256::Scalar>>(
    mut cs: CS,
    cells: &'a Cells<'a>,
    region: Region,
    last: Option<usize>,
  ) -> Result<(Self, [Lc; 2]), SynthesisError> {
    let last = OneHot::alloc(cs.namespace(|| "last block"), region.blocks, last)?;
    let mut digest = Vec::with_capacity(2);
    for h in 0..2 {
      let states: Vec<Lc> = (0..region.blocks).map(|j| cells.state(region.first + j, h)).collect();
      digest.push(last.select(cs.namespace(|| format!("digest half {h}")), &states)?);
    }
    let digest = [digest[0].clone(), digest[1].clone()];
    Ok((Message { cells, region, last }, digest))
  }

  /// Reads `len` bytes starting at the private byte offset `at` from the start of the message.
  ///
  /// Two selectors find the chunk that holds the first byte. One picks its block, and the rules
  /// read that block and the blocks after it that the window reaches. The other picks the chunk
  /// within the block, and the rules read the chunks from there on. Selecting the block first
  /// costs one rule per block of the region for each chunk position the window reaches, which is
  /// its chunks plus three. One selector over every chunk start would cost four times as many for
  /// each chunk of the window.
  ///
  /// The chunks are split into bytes, and a shifter drops the first `at mod 16` of them in four
  /// stages of 8, 4, 2 and 1 bytes, each stage one choice per byte. A last rule keeps the window
  /// inside the message's blocks up to its last one. The signature fixes those blocks only, so a
  /// prover could write anything into a later block.
  ///
  /// A witness generator, which ignores the rules, takes the selections, the chunks' bits and the
  /// choices natively.
  pub fn read<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    mut cs: CS,
    at: Option<usize>,
    len: usize,
  ) -> Result<Window, SynthesisError> {
    let chunks = (len + CHUNK_BYTES - 1).div_ceil(CHUNK_BYTES);
    // The window's first chunk is one of the four of its block, so it reaches this many blocks.
    let blocks = (CHUNKS_PER_BLOCK - 1 + chunks).div_ceil(CHUNKS_PER_BLOCK);
    let block = OneHot::alloc(cs.namespace(|| "block"), self.region.blocks, at.map(|a| a / 64))?;
    let chunk_in_block = at.map(|a| a % 64 / CHUNK_BYTES);
    let chunk = OneHot::alloc(cs.namespace(|| "chunk"), CHUNKS_PER_BLOCK, chunk_in_block)?;
    let shift =
      alloc_bits(cs.namespace(|| "shift"), at.map(|a| small_bits((a % CHUNK_BYTES) as u64, 4)), 4)?;
    let offset = block.index().scale(t256::Scalar::from(64))
      + &chunk.index().scale(t256::Scalar::from(CHUNK_BYTES as u64))
      + &pack(&shift);

    // The window ends within the last block: 64 · (last + 1) − (offset + len) is not negative.
    let end_of_last =
      (self.last.index() + &Lc::constant(t256::Scalar::ONE)).scale(t256::Scalar::from(64));
    let room = end_of_last - &offset - &Lc::small(len as u64);
    range_check(cs.namespace(|| "inside the signed blocks"), &room, OFFSET_BITS)?;
    if cs.is_witness_generator() {
      let at = at.ok_or(SynthesisError::AssignmentMissing)?;
      return Ok(Window { bytes: self.read_values(&mut cs, at, len, chunks)?, offset });
    }

    // The chunks at positions 0 to chunks + 2, counted from the first chunk of the selected block
    // across the block sequence: reached[r] is the chunk at position r. The window's chunk k
    // selects among reached[k..k + 4], so every position up to chunks + 2 is read and no other
    // is selected.
    let reached_count = chunks + CHUNKS_PER_BLOCK - 1;
    debug_assert!(reached_count <= CHUNKS_PER_BLOCK * blocks);
    let mut reached = Vec::with_capacity(reached_count);
    for r in 0..reached_count {
      let entries: Vec<Lc> = (0..self.region.blocks)
        .map(|b| self.cells.chunk(CHUNKS_PER_BLOCK * (self.region.first + b) + r))
        .collect();
      reached.push(block.select(cs.namespace(|| format!("reached {r}")), &entries)?);
    }

    let mut window = Vec::with_capacity(CHUNK_BYTES * chunks);
    for k in 0..chunks {
      let entries = &reached[k..k + CHUNKS_PER_BLOCK];
      let value = chunk.select(cs.namespace(|| format!("chunk {k}")), entries)?;
      let chunk_bits = bits(cs.namespace(|| format!("chunk {k} bits")), &value, 8 * CHUNK_BYTES)?;
      window.extend(bytes(&chunk_bits));
    }

    for (stage, (bit, step)) in shift.iter().zip([8, 4, 2, 1]).enumerate() {
      let keep = len + step - 1;
      let bit = Lc::bit(bit);
      window = (0..keep)
        .map(|t| {
          mux(
            cs.namespace(|| format!("shift {stage} byte {t}")),
            &bit,
            &window[t],
            &window[t + step],
          )
        })
        .collect::<Result<_, _>>()?;
    }
    Ok(Window { bytes: window, offset })
  }

  /// The values that [`Message::read`] allocates after its range check, at the offset `at`,
  /// computed natively, in its order: the block selector's products for each chunk position
  /// reached, the chunk selector's products and the 128 bits of each chunk of the window, and the
  /// choices of each stage. Returns the window's bytes, the last stage's slots.
  fn read_values<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
    at: usize,
    len: usize,
    chunks: usize,
  ) -> Result<Vec<Lc>, SynthesisError> {
    let blocks = self.region.blocks;
    let (block, chunk) = (at / 64, at % 64 / CHUNK_BYTES);
    let reached_count = chunks + CHUNKS_PER_BLOCK - 1;
    let stages = (len + 7) + (len + 3) + (len + 1);
    let mut values = Values::with_capacity(
      reached_count * (blocks - 1) + chunks * (CHUNKS_PER_BLOCK - 1 + 8 * CHUNK_BYTES) + stages,
    );
    let mut reached = Vec::with_capacity(reached_count);
    for r in 0..reached_count {
      let entry = |b: usize| {
        let value = self.cells.chunk(CHUNKS_PER_BLOCK * (self.region.first + b) + r).value;
        value.ok_or(SynthesisError::AssignmentMissing)
      };
      let first = entry(0)?;
      let chosen = if block < blocks { entry(block)? } else { first };
      reached.push(select_values(
        &mut values,
        blocks,
        block,
        |b| if b == 0 { first } else { chosen },
      ));
    }

    let mut window = Vec::with_capacity(CHUNK_BYTES * chunks);
    for k in 0..chunks {
      let value = select_values(&mut values, CHUNKS_PER_BLOCK, chunk, |j| reached[k + j]);
      values.field_bits(&value, 8 * CHUNK_BYTES);
      window.extend(low_bytes(&value).map(|b| t256::Scalar::from(u64::from(b))));
    }

    let shift = small_bits((at % CHUNK_BYTES) as u64, 4);
    for (stage, (&bit, step)) in shift.iter().zip([8, 4, 2, 1]).enumerate() {
      let keep = len + step - 1;
      window = (0..keep).map(|t| window[if bit { t + step } else { t }]).collect();
      if stage < 3 {
        values.0.extend(&window);
      }
    }
    cs.extend_aux(&values.0);
    window.iter().map(|&byte| Lc::alloc(&mut *cs, Some(byte))).collect()
  }
}
