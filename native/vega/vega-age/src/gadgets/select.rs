//! The one-hot selector of clause 5.3.
//!
//! A circuit's coefficients are fixed, so they cannot point at a different table entry for each
//! position. A selector reads the entry at a private or public index with rules instead.

use std::ops::Range;

use bellpepper_core::{
  ConstraintSystem, SynthesisError,
  boolean::{AllocatedBit, Boolean},
};
use ff::Field;
use vega_prover::provider::pt256::t256;

use super::lc::{Lc, equal, mul};
use super::values::Values;

/// One bit per index 0..n, exactly one of them set.
pub struct OneHot {
  bits: Vec<Boolean>,
}

impl OneHot {
  /// Steps 1 and 2 of clause 5.3: one bit slot per index, and the rule that the bits add up to one.
  pub fn alloc<CS: ConstraintSystem<t256::Scalar>>(
    mut cs: CS,
    n: usize,
    index: Option<usize>,
  ) -> Result<Self, SynthesisError> {
    let bits = (0..n)
      .map(|j| {
        let bit = index.map(|i| i == j);
        AllocatedBit::alloc(cs.namespace(|| format!("bit {j}")), bit).map(Boolean::from)
      })
      .collect::<Result<Vec<_>, _>>()?;
    let sum = bits.iter().fold(Lc::zero(), |sum, bit| sum + &Lc::bit(bit));
    equal(cs.namespace(|| "one bit set"), &sum, &Lc::constant(t256::Scalar::ONE));
    Ok(OneHot { bits })
  }

  /// The selected index, the sum of j · s_j. Step 3 of clause 5.3 ties it to a value.
  pub fn index(&self) -> Lc {
    self
      .bits
      .iter()
      .enumerate()
      .fold(Lc::zero(), |sum, (j, bit)| sum + &Lc::bit(bit).scale(t256::Scalar::from(j as u64)))
  }

  /// One when the selected index lies in `range`, and zero otherwise: the sum of its bits there.
  pub fn within(&self, range: Range<usize>) -> Lc {
    self.bits[range].iter().fold(Lc::zero(), |sum, bit| sum + &Lc::bit(bit))
  }

  /// Step 4 of clause 5.3: the entry at the selected index, with one rule per entry after the
  /// first. The bits sum to one, so the first entry's bit is one minus the others, and the entry
  /// at the selected index is the first entry plus, for each other j, s_j · (t_j − t_0). The sum
  /// of s_j · t_j over all j is the same value.
  pub fn select<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    mut cs: CS,
    entries: &[Lc],
  ) -> Result<Lc, SynthesisError> {
    assert_eq!(entries.len(), self.bits.len());
    let mut sum = entries[0].clone();
    for (j, (bit, entry)) in self.bits.iter().zip(entries).enumerate().skip(1) {
      let difference = entry - &entries[0];
      sum = sum + &mul(cs.namespace(|| format!("entry {j}")), &Lc::bit(bit), &difference)?;
    }
    Ok(sum)
  }
}

/// The values of [`OneHot::alloc`] at `index` among `n`: its bits, the one at `index` set and
/// none if `index` is not below `n`.
pub fn one_hot_values(values: &mut Values, n: usize, index: usize) {
  values.0.extend((0..n).map(|j| if j == index { t256::Scalar::ONE } else { t256::Scalar::ZERO }));
}

/// The values of [`OneHot::select`] over `n` entries, whose bits are set at `index` alone (none if
/// `index` is not below `n`), and `entry(j)` the value of entry j: for each entry after the first,
/// s_j · (t_j − t_0), which is t_j − t_0 at the index and zero elsewhere. Returns the selected
/// value, t_0 plus those products.
pub fn select_values(
  values: &mut Values,
  n: usize,
  index: usize,
  entry: impl Fn(usize) -> t256::Scalar,
) -> t256::Scalar {
  let first = entry(0);
  let selected = if (1..n).contains(&index) { entry(index) - first } else { t256::Scalar::ZERO };
  values.0.extend((1..n).map(|j| if j == index { selected } else { t256::Scalar::ZERO }));
  first + selected
}
