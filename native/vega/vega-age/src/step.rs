//! The step circuit (clauses 4.2 and 5.3): SHA-256 compressions at a public position.
//!
//! Every step instance has the same rules. The instance at position j reads block j, the state
//! before it and the state after it from the shared table, and checks that compressing the block
//! from the state before gives the state after. The state before the signed message's first
//! position is the table's start state, and the state before every other message's first
//! position is the SHA-256 initial value. All step instances together therefore check every hash
//! chain of the table.
//!
//! The rules name no position, so they read the table through the one-hot selector of clause
//! 5.3, whose index is the public position. The application checks that instance j reports
//! position j.
//!
//! In the full statement's SD-JWT layout ([`crate::table::FULL_SD_JWT`]) an instance checks two
//! compressions, at positions 2i and 2i + 1: the second starts from the first's result, since no
//! message starts at an odd position, and reads no state before it from the table.
//!
//! An SD-JWT's step instances also scan their blocks for the keys nbf and exp (see
//! [`crate::sdjwt`]).
//!
//! The witness does not synthesize the step: [`Step::assignment`] computes the values that a
//! witness generator records when it synthesizes the step, natively, in their order. A witness
//! generator synthesizing the step takes the same values; every other constraint system builds
//! the rules.

use std::sync::Arc;

use bellpepper::gadgets::{sha256::sha256_compression_function, uint32::UInt32};
use bellpepper_core::{ConstraintSystem, SynthesisError, boolean::Boolean, num::AllocatedNum};
use vega_prover::provider::{T256HyraxEngine, pt256::t256};
use vega_prover::traits::circuit::VegaCircuit;

use crate::app::{Instance, Segment};
use crate::gadgets::bits::{bits, pack};
use crate::gadgets::lc::{Lc, equal, low_bytes};
use crate::gadgets::select::{OneHot, one_hot_values, select_values};
use crate::gadgets::sha256;
use crate::gadgets::values::Values;
use crate::sdjwt;
use crate::table::{self, AGE, CHUNK_BYTES, CHUNKS_PER_BLOCK, Cells, Layout, Table};

/// The step instance at one position of the table.
#[derive(Clone, Debug)]
pub struct Step {
  /// The instance's position: its index among the layout's instances.
  pub position: usize,
  /// The table, or none when setup only builds the shape.
  pub table: Option<Arc<Table>>,
  /// Whether the step also scans its blocks for nbf and exp, which only an SD-JWT needs.
  pub scan: bool,
  /// The table's layout, which sets the chains' starts and the compressions per instance.
  pub layout: Layout,
}

impl Step {
  /// A step without values, for setup.
  pub fn blank(position: usize, scan: bool) -> Self {
    Self::blank_in(AGE, position, scan)
  }

  /// A step of `layout` without values, for setup.
  pub fn blank_in(layout: Layout, position: usize, scan: bool) -> Self {
    Step { position, table: None, scan, layout }
  }

  /// The step at `position` of a table, in the table's layout. It scans for nbf and exp when the
  /// table has scan entries.
  pub fn new(position: usize, table: Arc<Table>) -> Self {
    let (scan, layout) = (table.scan.is_some(), table.layout);
    Step { position, table: Some(table), scan, layout }
  }

  /// The instance's values besides the shared segment, computed natively: those that the
  /// prover's witness generator, `SatisfyingAssignment`, records when it synthesizes the step, in
  /// their order and with their values. The precommitted segment holds the position, its one
  /// public value, and the values of the selector, the compressions and the scans; the rest
  /// segment is empty.
  pub fn assignment(&self) -> Result<Instance, SynthesisError> {
    let position = t256::Scalar::from(self.position as u64);
    let private = self.precommitted_values()?.0;
    Ok(Instance {
      precommitted: Segment { private, public: vec![position] },
      rest: Segment::default(),
      public_values: vec![position],
    })
  }

  /// The private values of the precommitted segment, in the order of
  /// [`VegaCircuit::precommitted`]: the selector's bits, then for each compression its values
  /// ([`compression_values`]) and those of its scan ([`sdjwt::scan_values`]).
  fn precommitted_values(&self) -> Result<Values, SynthesisError> {
    let table = self.table.as_deref().ok_or(SynthesisError::AssignmentMissing)?;
    let layout = &self.layout;
    let mut values = Values::with_capacity(layout.budget);
    one_hot_values(&mut values, layout.instances(), self.position);
    let mut result = None;
    for k in 0..layout.per_instance {
      let (block, words) =
        compression_values(&mut values, table, layout, self.position, k, result.take());
      if self.scan {
        sdjwt::scan_values(&mut values, table, layout, self.position, &block, k)?;
      }
      result = Some(words);
    }
    Ok(values)
  }
}

/// The big-endian words of bytes.
fn words<const N: usize>(bytes: &[u8]) -> [u32; N] {
  std::array::from_fn(|i| u32::from_be_bytes(bytes[4 * i..4 * i + 4].try_into().expect("4 bytes")))
}

/// The values of [`compression`] for the instance whose selector is set at `index`: the
/// selections of block j's chunks and their bits, those of the state before it and its bits,
/// unless it is `before`, the instance's previous result, the values of bellpepper's compression
/// ([`sha256::compression`]) and the selections of the state after it. Returns block j as the
/// rules read it and the state after it.
fn compression_values(
  values: &mut Values,
  table: &Table,
  layout: &Layout,
  index: usize,
  k: usize,
  before: Option<[u32; 8]>,
) -> ([u8; 64], [u32; 8]) {
  let n = layout.instances();
  let position = |i: usize| layout.per_instance * i + k;

  let mut block = [0u8; 64];
  for c in 0..CHUNKS_PER_BLOCK {
    let chunk =
      select_values(values, n, index, |i| table.chunk_value(CHUNKS_PER_BLOCK * position(i) + c));
    let bytes = low_bytes(&chunk);
    values.byte_bits(&bytes);
    block[CHUNK_BYTES * c..CHUNK_BYTES * (c + 1)].copy_from_slice(&bytes);
  }

  let state = match before {
    Some(words) => words,
    None => {
      let mut state = [0u8; 32];
      for h in 0..2 {
        let half =
          select_values(values, n, index, |i| table.state_before_value(layout, position(i), h));
        let bytes = low_bytes(&half);
        values.byte_bits(&bytes);
        state[CHUNK_BYTES * h..CHUNK_BYTES * (h + 1)].copy_from_slice(&bytes);
      }
      words(&state)
    }
  };

  let after = sha256::compression(values, &words(&block), &state);
  for h in 0..2 {
    select_values(values, n, index, |i| table.state_value(position(i), h));
  }
  (block, after)
}

/// One compression of a step instance, at the positions `per_instance · i + k` of its
/// instances i: block j's 512 bits from its chunks, the state before it (the table's, selected,
/// or `before`, the instance's previous result), the compression, and the state after it, which
/// the table holds. Returns the block's bits and the result.
fn compression<CS: ConstraintSystem<t256::Scalar>>(
  cs: &mut CS,
  cells: &Cells,
  layout: &Layout,
  selector: &OneHot,
  k: usize,
  before: Option<Vec<UInt32>>,
) -> Result<(Vec<Boolean>, Vec<UInt32>), SynthesisError> {
  let positions: Vec<usize> =
    (0..layout.instances()).map(|i| layout.per_instance * i + k).collect();

  // Block j, as 512 bits.
  let mut block = Vec::with_capacity(512);
  for c in 0..CHUNKS_PER_BLOCK {
    let entries: Vec<Lc> =
      positions.iter().map(|&j| cells.chunk(CHUNKS_PER_BLOCK * j + c)).collect();
    let chunk = selector.select(cs.namespace(|| format!("chunk {c}")), &entries)?;
    block.extend(bits(cs.namespace(|| format!("chunk {c} bits")), &chunk, 128)?);
  }

  // The state before block j.
  let words = match before {
    Some(words) => words,
    None => {
      let mut before = Vec::with_capacity(256);
      for h in 0..2 {
        let entries: Vec<Lc> =
          positions.iter().map(|&j| cells.state_before_in(layout, j, h)).collect();
        let half = selector.select(cs.namespace(|| format!("state before half {h}")), &entries)?;
        before.extend(bits(cs.namespace(|| format!("state before half {h} bits")), &half, 128)?);
      }
      before.chunks(32).map(UInt32::from_bits_be).collect()
    }
  };

  let words = sha256_compression_function(cs.namespace(|| "compression"), &block, &words)?;
  let after: Vec<Boolean> = words.iter().cloned().flat_map(UInt32::into_bits_be).collect();

  // The state after block j is the one the table holds.
  for h in 0..2 {
    let entries: Vec<Lc> = positions.iter().map(|&j| cells.state(j, h)).collect();
    let half = selector.select(cs.namespace(|| format!("state after half {h}")), &entries)?;
    let computed = pack(&after[128 * h..128 * (h + 1)]);
    equal(cs.namespace(|| format!("state after half {h} matches")), &computed, &half);
  }
  Ok((block, words))
}

impl VegaCircuit<T256HyraxEngine> for Step {
  fn public_values(&self) -> Result<Vec<t256::Scalar>, SynthesisError> {
    Ok(vec![t256::Scalar::from(self.position as u64)])
  }

  fn shared<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
  ) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
    table::allocate(cs.namespace(|| "table"), self.table.as_deref(), self.scan)
  }

  /// All rules of the step. They go in the precommitted segment, which the prover commits to
  /// once per credential and reuses for every presentation (clause 5.4).
  fn precommitted<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
    shared: &[AllocatedNum<t256::Scalar>],
  ) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
    // A witness generator records the values and ignores the rules.
    if cs.is_witness_generator() {
      cs.extend_inputs(&[t256::Scalar::from(self.position as u64)]);
      cs.extend_aux(&self.precommitted_values()?.0);
      return Ok(vec![]);
    }
    let cells = Cells(shared);
    let layout = &self.layout;

    // The selector's index is the public position (clause 5.3, steps 1 to 3).
    let position = AllocatedNum::alloc_input(cs.namespace(|| "position"), || {
      Ok(t256::Scalar::from(self.position as u64))
    })?;
    let selector =
      OneHot::alloc(cs.namespace(|| "selector"), layout.instances(), Some(self.position))?;
    equal(cs.namespace(|| "selected position"), &selector.index(), &Lc::num(&position));

    if layout.per_instance == 1 {
      let (block, _) = compression(cs, &cells, layout, &selector, 0, None)?;
      if self.scan {
        sdjwt::scan_in(cs.namespace(|| "scan"), &cells, &selector, &block, layout, 0)?;
      }
      return Ok(vec![]);
    }
    // The second compression of an instance starts from the first's result: no message starts
    // at its positions (`Layout::chains_within_instances`).
    debug_assert!(layout.chains_within_instances());
    let mut result = None;
    for k in 0..layout.per_instance {
      let cs = &mut cs.namespace(|| format!("compression {k}"));
      let (block, words) = compression(cs, &cells, layout, &selector, k, result.take())?;
      if self.scan {
        sdjwt::scan_in(cs.namespace(|| "scan"), &cells, &selector, &block, layout, k)?;
      }
      result = Some(words);
    }
    Ok(vec![])
  }

  fn num_challenges(&self) -> usize {
    0
  }

  /// The step has no presentation-specific rules, so its rest segment is empty.
  fn synthesize<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    _: &mut CS,
    _: &[AllocatedNum<t256::Scalar>],
    _: &[AllocatedNum<t256::Scalar>],
    _: Option<&[t256::Scalar]>,
  ) -> Result<(), SynthesisError> {
    Ok(())
  }
}
