//! Weighted sums of slots and the basic rules over them (clause 5.2).
//!
//! A rule of the circuit states that the product of two weighted sums equals a third one. An
//! [`Lc`] is one such weighted sum, carried together with its value so that the prover can
//! compute the values of new slots. While setup builds the shape, no value is known and every
//! value is `None`.

use std::ops::{Add, Sub};

use bellpepper_core::{
  ConstraintSystem, Index, LinearCombination, SynthesisError, Variable, boolean::Boolean,
  num::AllocatedNum,
};
use ff::{Field, FromUniformBytes, PrimeField};
use vega_prover::provider::pt256::t256;

/// A weighted sum of slots, with its value when the value is known.
#[derive(Clone)]
pub struct Lc {
  pub lc: LinearCombination<t256::Scalar>,
  pub value: Option<t256::Scalar>,
}

/// The slot that always holds one. Constants are multiples of it.
pub fn one() -> Variable {
  Variable::new_unchecked(Index::Input(0))
}

impl Lc {
  pub fn zero() -> Self {
    Lc { lc: LinearCombination::zero(), value: Some(t256::Scalar::ZERO) }
  }

  pub fn constant(c: t256::Scalar) -> Self {
    Lc { lc: LinearCombination::zero() + (c, one()), value: Some(c) }
  }

  pub fn small(c: u64) -> Self {
    Self::constant(t256::Scalar::from(c))
  }

  pub fn num(n: &AllocatedNum<t256::Scalar>) -> Self {
    Lc { lc: LinearCombination::from_variable(n.get_variable()), value: n.get_value() }
  }

  pub fn bit(b: &Boolean) -> Self {
    Lc { lc: b.lc(one(), t256::Scalar::ONE), value: b.get_value().map(t256::Scalar::from) }
  }

  /// A new slot holding `value`.
  pub fn alloc<CS: ConstraintSystem<t256::Scalar>>(
    mut cs: CS,
    value: Option<t256::Scalar>,
  ) -> Result<Self, SynthesisError> {
    let var = cs.alloc(|| "value", || value.ok_or(SynthesisError::AssignmentMissing))?;
    Ok(Lc { lc: LinearCombination::from_variable(var), value })
  }

  pub fn scale(&self, c: t256::Scalar) -> Self {
    Lc { lc: LinearCombination::zero() + (c, &self.lc), value: self.value.map(|v| v * c) }
  }
}

impl Add<&Lc> for Lc {
  type Output = Lc;
  fn add(self, other: &Lc) -> Lc {
    Lc { lc: self.lc + &other.lc, value: val([self.value, other.value], |[a, b]| a + b) }
  }
}

impl Sub<&Lc> for Lc {
  type Output = Lc;
  fn sub(self, other: &Lc) -> Lc {
    Lc { lc: self.lc - &other.lc, value: val([self.value, other.value], |[a, b]| a - b) }
  }
}

impl Add<&Lc> for &Lc {
  type Output = Lc;
  fn add(self, other: &Lc) -> Lc {
    self.clone() + other
  }
}

impl Sub<&Lc> for &Lc {
  type Output = Lc;
  fn sub(self, other: &Lc) -> Lc {
    self.clone() - other
  }
}

/// Applies `f` to the values when all of them are known.
pub fn val<const N: usize>(
  inputs: [Option<t256::Scalar>; N],
  f: impl FnOnce([t256::Scalar; N]) -> t256::Scalar,
) -> Option<t256::Scalar> {
  let mut known = [t256::Scalar::ZERO; N];
  for (slot, input) in known.iter_mut().zip(inputs) {
    *slot = input?;
  }
  Some(f(known))
}

/// The inverse of a value, or zero for zero. A rule that needs the inverse of zero then fails,
/// instead of the prover stopping before the rules are checked.
pub fn inverse(v: t256::Scalar) -> t256::Scalar {
  Option::from(v.invert()).unwrap_or(t256::Scalar::ZERO)
}

/// Replaces each value by its [`inverse`], zero for zero, with one inversion (Montgomery's
/// trick): the products of the nonzero values before each, then the inverse of all of them,
/// which each step back turns into the inverse of one value and of the product before it.
pub fn inverse_all(values: &mut [t256::Scalar]) {
  let mut before = Vec::with_capacity(values.len());
  let mut product = t256::Scalar::ONE;
  for v in values.iter() {
    before.push(product);
    if !bool::from(v.is_zero()) {
      product *= v;
    }
  }
  let mut inv = inverse(product);
  for (v, before) in values.iter_mut().zip(before).rev() {
    if !bool::from(v.is_zero()) {
      let next = inv * *v;
      *v = inv * before;
      inv = next;
    }
  }
}

/// Adds the rule a · b = c.
pub fn product<CS: ConstraintSystem<t256::Scalar>>(mut cs: CS, a: &Lc, b: &Lc, c: &Lc) {
  cs.enforce(|| "product", |z| z + &a.lc, |z| z + &b.lc, |z| z + &c.lc);
}

/// Adds the rule a = b, written as (a − b) · 1 = 0.
pub fn equal<CS: ConstraintSystem<t256::Scalar>>(mut cs: CS, a: &Lc, b: &Lc) {
  cs.enforce(|| "equal", |z| z + &a.lc - &b.lc, |z| z + one(), |z| z);
}

/// A new slot holding a · b, with the rule that defines it.
pub fn mul<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  a: &Lc,
  b: &Lc,
) -> Result<Lc, SynthesisError> {
  let c = Lc::alloc(cs.namespace(|| "value"), val([a.value, b.value], |[a, b]| a * b))?;
  product(cs.namespace(|| "rule"), a, b, &c);
  Ok(c)
}

/// A new slot holding `if0` when `bit` is zero and `if1` when it is one. The one rule is
/// bit · (if1 − if0) = out − if0, so `bit` has to be a bit already.
pub fn mux<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  bit: &Lc,
  if0: &Lc,
  if1: &Lc,
) -> Result<Lc, SynthesisError> {
  let out = Lc::alloc(
    cs.namespace(|| "value"),
    val([bit.value, if0.value, if1.value], |[b, x, y]| x + b * (y - x)),
  )?;
  product(cs.namespace(|| "rule"), bit, &(if1 - if0), &(&out - if0));
  Ok(out)
}

/// Adds the rule that `a` is not zero: a slot holds its inverse, and a · inverse = 1.
pub fn nonzero<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  a: &Lc,
) -> Result<(), SynthesisError> {
  let inv = Lc::alloc(cs.namespace(|| "inverse"), a.value.map(inverse))?;
  product(cs.namespace(|| "rule"), a, &inv, &Lc::constant(t256::Scalar::ONE));
  Ok(())
}

/// Adds the rule that `a` is not zero when the bit `flag` is one. A slot holds the flag times the
/// inverse of `a`, and a · slot = flag. With the flag zero the slot is zero and the rule holds.
pub fn nonzero_if<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  flag: &Lc,
  a: &Lc,
) -> Result<(), SynthesisError> {
  let inv =
    Lc::alloc(cs.namespace(|| "inverse"), val([flag.value, a.value], |[f, a]| f * inverse(a)))?;
  product(cs.namespace(|| "rule"), a, &inv, flag);
  Ok(())
}

/// A new slot holding the value of `a`, with one rule. Values pass from the precommitted
/// segment to the rest segment in slots.
pub fn to_num<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  a: &Lc,
) -> Result<AllocatedNum<t256::Scalar>, SynthesisError> {
  let n = AllocatedNum::alloc(cs.namespace(|| "value"), || {
    a.value.ok_or(SynthesisError::AssignmentMissing)
  })?;
  equal(cs.namespace(|| "rule"), &Lc::num(&n), a);
  Ok(n)
}

/// The field element of a big-endian integer of at most 32 bytes, reduced modulo the field prime.
pub fn from_be(bytes: &[u8]) -> t256::Scalar {
  assert!(bytes.len() <= 32);
  let mut wide = [0u8; 64];
  for (i, b) in bytes.iter().rev().enumerate() {
    wide[i] = *b;
  }
  t256::Scalar::from_uniform_bytes(&wide)
}

/// The 32 big-endian bytes of a field element.
pub fn to_be(x: &t256::Scalar) -> [u8; 32] {
  let mut bytes = [0u8; 32];
  bytes.copy_from_slice(x.to_repr().as_ref());
  bytes.reverse();
  bytes
}

/// The low 16 bytes of a field element's integer, most significant first: the bytes of a
/// 128-bit value, as [`super::bits::bits`] splits them.
pub fn low_bytes(x: &t256::Scalar) -> [u8; 16] {
  to_be(x)[16..].try_into().expect("16 bytes")
}
