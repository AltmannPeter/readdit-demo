//! The shared table (clauses 5.3 and 5.4).
//!
//! The table holds two signed messages as SHA-256 blocks, one block per position, and the hash
//! state after each block. Positions 0 to 29 hold the end of the message the issuer signed.
//! Positions 30 and 31 hold the one attribute the presentation is about, whose digest the signed
//! message lists.
//!
//! The attribute's hash chain starts from the SHA-256 initial value. The signed message's chain
//! starts from the start state, a private table entry. The prover skips the blocks before the
//! first byte the core reads, and the start state is the hash state after them. An SD-JWT
//! header carries the issuer's certificate and fills about half of the signing input, so
//! skipping it halves the positions. The rules do not check the start state. A prover who
//! changes it must find a start state and blocks whose chain still ends at the digest the issuer
//! signed, which is a pseudo-preimage of SHA-256's compression function.
//!
//! The step circuit at position j checks that compressing block j from the state before it gives
//! the state after it. The core circuit reads the state after a message's last block, which is
//! the message's digest, and reads the message's bytes through windows.
//!
//! The regions have fixed sizes. The prover picks privately how many blocks to skip and each
//! message's last block, so the proof reveals the length of neither message.
//!
//! An SD-JWT's table holds six more entries, which its steps read to scan the payload for the
//! keys nbf and exp (see [`crate::sdjwt`]): the payload's phase as four bits, and whether the
//! payload lacks each key.
//!
//! The positions above are the age statement's layout ([`AGE`]). The full statement, age and
//! pseudonym ([`crate::pseudonym`]), places three more messages in the same 32 positions
//! ([`FULL_MDOC`], [`FULL_SD_JWT`]): the signed message's region 0 to 21, the birth date's
//! attribute 22 and 23, the `ssc` attribute 24 to 26, the pseudonym's message 28 and 29, and the
//! secret seed's message 30; positions 27 and 31 hold no message. Every message but the signed
//! one chains from the initial value.

use std::sync::atomic::{AtomicUsize, Ordering};

use bellpepper_core::{ConstraintSystem, SynthesisError, num::AllocatedNum};
use ff::Field;
use sha2::{Digest, Sha256, compress256};
use vega_prover::provider::pt256::t256;

use crate::gadgets::lc::{Lc, from_be};

/// The number of positions. Setup pads the number of step instances to a power of two, so the
/// table uses all of them. The real SD-JWT PID needs 23 blocks after the skipped ones, and the
/// real mdoc PID 20, so 16 positions are too few.
pub const POSITIONS: usize = 32;

/// Every byte offset into the table, and every character offset into its base64url text, is
/// below 2^11. Range checks on offsets use this many bits.
pub const OFFSET_BITS: usize = 11;
const _: () = assert!(64 * POSITIONS <= 1 << OFFSET_BITS);

/// A block is read by the core as four chunks of sixteen bytes, each one table entry.
pub const CHUNK_BYTES: usize = 16;
pub const CHUNKS_PER_BLOCK: usize = 4;

/// Per position, four block chunks and the two 128-bit halves of the state after the block.
const CELLS_PER_POSITION: usize = CHUNKS_PER_BLOCK + 2;

/// The two halves of the start state follow the cells of the last position.
const START: usize = CELLS_PER_POSITION * POSITIONS;

/// An SD-JWT's scan entries follow the start state.
const SCAN: usize = START + 2;

/// A run of positions that holds one message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
  pub first: usize,
  pub blocks: usize,
}

/// The message the issuer signed: the COSE Sig_structure of an mdoc MSO, or the JWS signing
/// input of an SD-JWT. The region holds its blocks after the skipped ones.
pub const SIGNED: Region = Region { first: 0, blocks: 30 };

/// The attribute: the IssuerSignedItemBytes of an mdoc item, or an SD-JWT disclosure.
pub const ATTRIBUTE: Region = Region { first: 30, blocks: 2 };

/// Where the table holds each message, and how the step instances read it.
///
/// The age statement's layout is [`AGE`]: [`SIGNED`] and [`ATTRIBUTE`], one compression per
/// step instance. The full nym_auth statement, age verification plus the pseudonym
/// (`crate::pseudonym`), adds three messages: the attribute `ssc` (its mdoc item or SD-JWT
/// disclosure, at most three blocks, whose digest the signed message lists), the secret seed's
/// one block, whose digest is `ssc`'s value, and the pseudonym's two blocks, whose digest is the
/// pseudonym. The signed region gives up ten blocks, so the table keeps its 32 positions: the
/// real PIDs need 20 (mdoc) and 23 (SD-JWT) blocks after the skipped ones, and nym_auth's
/// attestation 7 and 9.
///
/// Every message but the signed one chains from the SHA-256 initial value; the signed one chains
/// from the start state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
  pub signed: Region,
  pub attribute: Region,
  /// The full statement's messages: the `ssc` attribute, the secret seed and the pseudonym.
  pub pseudonym: Option<PseudonymRegions>,
  /// The compressions each step instance checks, at positions `per_instance · i + k`.
  pub per_instance: usize,
  /// The rules and the padded values every circuit of the layout fits in (`crate::app`).
  pub budget: usize,
}

/// The positions of the full statement's messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PseudonymRegions {
  /// The IssuerSignedItemBytes of the mdoc item `ssc` (two blocks), or the SD-JWT disclosure of
  /// `ssc` (three: its value is 64 hex digits, in base64url).
  pub ssc: Region,
  /// The secret seed's SHA-256 message, one block.
  pub seed: Region,
  /// The pseudonym's SHA-256 message, two blocks.
  pub nym: Region,
}

/// The age statement's layout.
pub const AGE: Layout = Layout {
  signed: SIGNED,
  attribute: ATTRIBUTE,
  pseudonym: None,
  per_instance: 1,
  budget: 1 << 15,
};

/// The full statement's regions, the same for both formats. Every region starts at an even
/// position, so a step instance of two compressions never starts a chain at its second
/// ([`FULL_SD_JWT`]); positions 27 and 31 are unused. The mdoc's `ssc` item fills two of its
/// region's three blocks.
const FULL_REGIONS: PseudonymRegions = PseudonymRegions {
  ssc: Region { first: 24, blocks: 3 },
  seed: Region { first: 30, blocks: 1 },
  nym: Region { first: 28, blocks: 2 },
};

/// The full statement's layout for an mdoc: one compression per step instance; every circuit
/// fits in 2^15.
pub const FULL_MDOC: Layout = Layout {
  signed: Region { first: 0, blocks: 22 },
  attribute: Region { first: 22, blocks: 2 },
  pseudonym: Some(FULL_REGIONS),
  per_instance: 1,
  budget: 1 << 15,
};

/// The full statement's layout for an SD-JWT VC. Its core passes 2^15 (the `ssc` disclosure's
/// listed digest is base64url inside base64url, and its 64 hex digits are read from base64url and
/// decoded), and Vega pads the step to the core's size, so each step instance checks two
/// compressions and fills its 2^16: 16 instances of 2^16 in place of 32 half-empty ones.
pub const FULL_SD_JWT: Layout = Layout { per_instance: 2, budget: 1 << 16, ..FULL_MDOC };

impl Layout {
  /// The step instances: the positions over the compressions each checks.
  pub const fn instances(&self) -> usize {
    POSITIONS / self.per_instance
  }

  /// Whether every chain starts at an instance's first compression, so that each later
  /// compression of an instance continues from the one before it (`crate::step`).
  pub fn chains_within_instances(&self) -> bool {
    (0..POSITIONS)
      .filter(|j| j % self.per_instance != 0)
      .all(|j| j != self.signed.first && !self.starts_from_iv(j))
  }

  /// The positions whose chain starts from the initial value: every region's first but the
  /// signed message's, which starts from the start state.
  pub(crate) fn starts_from_iv(&self, j: usize) -> bool {
    j == self.attribute.first
      || self.pseudonym.is_some_and(|p| j == p.ssc.first || j == p.seed.first || j == p.nym.first)
  }
}

/// The SHA-256 initial value.
pub const IV: [u32; 8] =
  [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

/// The index of the block that ends a message of `len` bytes after padding, counted from the
/// message's first block.
pub fn last_block(len: usize) -> usize {
  (len + 8) / 64
}

/// The number of whole blocks before the byte at `offset`. The prover skips them.
pub fn blocks_before(offset: usize) -> usize {
  offset / 64
}

/// Half `h` of a 32-byte state as a 128-bit table entry.
pub fn state_half(state: &[u8; 32], h: usize) -> t256::Scalar {
  from_be(&state[CHUNK_BYTES * h..CHUNK_BYTES * (h + 1)])
}

/// The initial value as bytes.
pub fn iv_bytes() -> [u8; 32] {
  words_to_bytes(&IV)
}

fn words_to_bytes(words: &[u32; 8]) -> [u8; 32] {
  let mut bytes = [0u8; 32];
  for (i, w) in words.iter().enumerate() {
    bytes[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
  }
  bytes
}

/// The SHA-256 digest of a message.
pub fn sha256(message: &[u8]) -> [u8; 32] {
  Sha256::digest(message).into()
}

/// SHA-256 padding: a one bit, zeros, and the bit length as a 64-bit big-endian integer.
pub fn pad(message: &[u8]) -> Vec<u8> {
  let mut padded = message.to_vec();
  padded.push(0x80);
  while padded.len() % 64 != 56 {
    padded.push(0);
  }
  padded.extend_from_slice(&(8 * message.len() as u64).to_be_bytes());
  padded
}

fn bytes_to_words(bytes: &[u8; 32]) -> [u32; 8] {
  let mut words = [0u32; 8];
  for (i, w) in words.iter_mut().enumerate() {
    *w = u32::from_be_bytes(bytes[4 * i..4 * i + 4].try_into().expect("four bytes"));
  }
  words
}

/// Compresses the blocks one after the other, starting from `state`.
// sha2 0.10 takes its blocks as the deprecated generic-array type.
#[allow(deprecated)]
fn compress(state: &mut [u32; 8], blocks: &[u8]) {
  for block in blocks.chunks(64) {
    compress256(state, &[sha2::digest::generic_array::GenericArray::clone_from_slice(block)]);
  }
}

/// What an SD-JWT's steps read to scan the payload for nbf and exp, besides the blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scan {
  /// The table offset of the payload's first character, modulo 4. Four base64url characters
  /// encode three bytes, so the phase tells at which characters a decoded byte starts.
  pub phase: usize,
  /// Whether the payload lacks nbf, and whether it lacks exp. The steps look for a key only
  /// when the payload lacks it.
  pub absent: [bool; 2],
}

/// The values of the shared table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
  pub blocks: Vec<[u8; 64]>,
  /// The state after each block, as the 32 bytes of the digest it would give.
  pub states: Vec<[u8; 32]>,
  /// The start state: the state before the signed message's first block in the table.
  pub start: [u8; 32],
  /// The scan entries of an SD-JWT, or none for an mdoc.
  pub scan: Option<Scan>,
  /// Where each message sits.
  pub layout: Layout,
}

impl Table {
  /// Pads each message as SHA-256 does and places it in its region, without the first `skipped`
  /// blocks of the signed message. Unused blocks are zero.
  pub fn new(signed: &[u8], skipped: usize, attribute: &[u8]) -> Result<Self, String> {
    Self::with_messages(AGE, signed, skipped, &[(ATTRIBUTE, attribute)])
  }

  /// [`Table::new`] in `layout`: the signed message in its region, without its first `skipped`
  /// blocks, and each other message, padded, in its region.
  pub fn with_messages(
    layout: Layout,
    signed: &[u8],
    skipped: usize,
    messages: &[(Region, &[u8])],
  ) -> Result<Self, String> {
    let signed = pad(signed);
    let (before, kept) = signed.split_at((64 * skipped).min(signed.len()));
    let mut start = IV;
    compress(&mut start, before);
    let mut blocks = vec![[0u8; 64]; POSITIONS];
    let padded: Vec<(Region, Vec<u8>)> = std::iter::once((layout.signed, kept.to_vec()))
      .chain(messages.iter().map(|(region, message)| (*region, pad(message))))
      .collect();
    for (region, padded) in &padded {
      if padded.len() > 64 * region.blocks {
        return Err(format!(
          "a message of {} blocks does not fit in {} blocks",
          padded.len() / 64,
          region.blocks
        ));
      }
      for (j, block) in padded.chunks(64).enumerate() {
        blocks[region.first + j].copy_from_slice(block);
      }
    }
    Ok(Self::from_blocks_in(layout, blocks, words_to_bytes(&start)))
  }

  /// Hashes the blocks as the step circuits do: from the start state at the signed message's
  /// first position, and from the initial value at the attribute's.
  pub fn from_blocks(blocks: Vec<[u8; 64]>, start: [u8; 32]) -> Self {
    Self::from_blocks_in(AGE, blocks, start)
  }

  /// [`Table::from_blocks`] in `layout`: every region but the signed message's chains from the
  /// initial value.
  pub fn from_blocks_in(layout: Layout, blocks: Vec<[u8; 64]>, start: [u8; 32]) -> Self {
    assert_eq!(blocks.len(), POSITIONS);
    let mut state = IV;
    let states = blocks
      .iter()
      .enumerate()
      .map(|(j, block)| {
        if j == layout.signed.first {
          state = bytes_to_words(&start);
        }
        if layout.starts_from_iv(j) {
          state = IV;
        }
        compress(&mut state, block);
        words_to_bytes(&state)
      })
      .collect();
    Table { blocks, states, start, scan: None, layout }
  }

  /// The bytes of a region, all its blocks in order.
  pub fn region_bytes(&self, region: Region) -> Vec<u8> {
    self.blocks[region.first..region.first + region.blocks].concat()
  }

  /// The value of chunk `c` of the shared segment, as [`Cells::chunk`] reads it: counting from
  /// the first chunk of position 0, or zero past the end.
  pub fn chunk_value(&self, c: usize) -> t256::Scalar {
    if c < CHUNKS_PER_BLOCK * POSITIONS {
      let k = c % CHUNKS_PER_BLOCK;
      from_be(&self.blocks[c / CHUNKS_PER_BLOCK][CHUNK_BYTES * k..CHUNK_BYTES * (k + 1)])
    } else {
      t256::Scalar::ZERO
    }
  }

  /// The value of half `h` of the state after position `j`, as [`Cells::state`] reads it.
  pub fn state_value(&self, j: usize, h: usize) -> t256::Scalar {
    state_half(&self.states[j], h)
  }

  /// The value of half `h` of the state before position `j` in `layout`, as
  /// [`Cells::state_before_in`] reads it.
  pub fn state_before_value(&self, layout: &Layout, j: usize, h: usize) -> t256::Scalar {
    if j == layout.signed.first {
      state_half(&self.start, h)
    } else if layout.starts_from_iv(j) {
      state_half(&iv_bytes(), h)
    } else {
      self.state_value(j - 1, h)
    }
  }
}

/// How many times a circuit allocated the shared segment: once for each synthesis of a step or a
/// core circuit, whatever the constraint system. A caller reads it to check that a load from the
/// circuits as data synthesizes no circuit.
pub fn syntheses() -> usize {
  SYNTHESES.load(Ordering::Relaxed)
}

static SYNTHESES: AtomicUsize = AtomicUsize::new(0);

/// Allocates the shared segment: for each position, the four chunks of its block, then the two
/// halves of the state after it, and then the two halves of the start state. With `scan`, the four
/// phase bits and the flags for a missing nbf and a missing exp come last. The step and the core
/// circuit both allocate it with this function, so both lay it out the same way (clause 5.6). Setup
/// passes no table.
pub fn allocate<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  table: Option<&Table>,
  scan: bool,
) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
  SYNTHESES.fetch_add(1, Ordering::Relaxed);
  let mut cells = Vec::with_capacity(SCAN + 6);
  for j in 0..POSITIONS {
    for k in 0..CHUNKS_PER_BLOCK {
      let value = table.map(|t| from_be(&t.blocks[j][CHUNK_BYTES * k..CHUNK_BYTES * (k + 1)]));
      cells.push(AllocatedNum::alloc(cs.namespace(|| format!("block {j} chunk {k}")), || {
        value.ok_or(SynthesisError::AssignmentMissing)
      })?);
    }
    for h in 0..2 {
      let value = table.map(|t| state_half(&t.states[j], h));
      cells.push(AllocatedNum::alloc(cs.namespace(|| format!("state {j} half {h}")), || {
        value.ok_or(SynthesisError::AssignmentMissing)
      })?);
    }
  }
  for h in 0..2 {
    let value = table.map(|t| state_half(&t.start, h));
    cells.push(AllocatedNum::alloc(cs.namespace(|| format!("start state half {h}")), || {
      value.ok_or(SynthesisError::AssignmentMissing)
    })?);
  }
  if scan {
    let entries = table.and_then(|t| t.scan);
    let phase = (0..4).map(|r| (format!("payload phase {r}"), entries.map(|e| e.phase == r)));
    let absent = ["nbf", "exp"].into_iter().enumerate();
    let absent = absent.map(|(i, key)| (format!("{key} absent"), entries.map(|e| e.absent[i])));
    for (name, flag) in phase.chain(absent) {
      let value = flag.map(|f| t256::Scalar::from(u64::from(f)));
      cells.push(AllocatedNum::alloc(cs.namespace(|| name), || {
        value.ok_or(SynthesisError::AssignmentMissing)
      })?);
    }
  }
  Ok(cells)
}

/// The shared segment as the circuits read it.
pub struct Cells<'a>(pub &'a [AllocatedNum<t256::Scalar>]);

impl Cells<'_> {
  /// Chunk `c` of the table, counting from the first chunk of position 0, or zero past the end.
  pub fn chunk(&self, c: usize) -> Lc {
    if c < CHUNKS_PER_BLOCK * POSITIONS {
      let j = c / CHUNKS_PER_BLOCK;
      Lc::num(&self.0[CELLS_PER_POSITION * j + c % CHUNKS_PER_BLOCK])
    } else {
      Lc::zero()
    }
  }

  /// Half `h` of the state after position `j`.
  pub fn state(&self, j: usize, h: usize) -> Lc {
    Lc::num(&self.0[CELLS_PER_POSITION * j + CHUNKS_PER_BLOCK + h])
  }

  /// Half `h` of the state before position `j`: the start state before the signed message, the
  /// initial value before the attribute, and otherwise the state after position j − 1.
  pub fn state_before(&self, j: usize, h: usize) -> Lc {
    self.state_before_in(&AGE, j, h)
  }

  /// [`Cells::state_before`] in `layout`: the start state before the signed message, the initial
  /// value before every other region, and otherwise the state after position j − 1.
  pub fn state_before_in(&self, layout: &Layout, j: usize, h: usize) -> Lc {
    if j == layout.signed.first {
      Lc::num(&self.0[START + h])
    } else if layout.starts_from_iv(j) {
      Lc::constant(state_half(&iv_bytes(), h))
    } else {
      self.state(j - 1, h)
    }
  }

  /// An SD-JWT's scan entries: the four phase bits, of which the one at the payload's phase is
  /// set, and the flags that the payload lacks nbf and exp.
  pub fn scan(&self) -> ([Lc; 4], [Lc; 2]) {
    let entry = |i: usize| Lc::num(&self.0[SCAN + i]);
    (std::array::from_fn(entry), std::array::from_fn(|i| entry(4 + i)))
  }
}
