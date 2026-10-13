//! Range constraints, bytes and comparisons with constants (clause 5.2.3).
//!
//! Bit lists are most significant bit first throughout, which is the order of SHA-256, of
//! big-endian bytes and of double-and-add.

use bellpepper_core::{
  ConstraintSystem, SynthesisError,
  boolean::{AllocatedBit, Boolean},
};
use ff::{Field, PrimeField};
use vega_prover::provider::pt256::t256;

use super::lc::{Lc, equal, from_be, mul, product};
use super::values::Values;

/// The bits of a field element, least significant first.
fn le_bits(x: &t256::Scalar) -> Vec<bool> {
  x.to_repr().as_ref().iter().flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1)).collect()
}

/// The bits of a byte string, most significant first.
pub fn be_bits(bytes: &[u8]) -> Vec<bool> {
  bytes.iter().flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1)).collect()
}

/// The `n` low bits of an integer, most significant first.
pub fn small_bits(v: u64, n: usize) -> Vec<bool> {
  (0..n).rev().map(|i| (v >> i) & 1 == 1).collect()
}

/// `n` new bit slots, each with its bit rule b · (b − 1) = 0.
pub fn alloc_bits<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  bits: Option<Vec<bool>>,
  n: usize,
) -> Result<Vec<Boolean>, SynthesisError> {
  (0..n)
    .map(|i| {
      let bit = bits.as_ref().map(|b| b[i]);
      AllocatedBit::alloc(cs.namespace(|| format!("bit {i}")), bit).map(Boolean::from)
    })
    .collect()
}

/// The integer with these bits.
pub fn pack(bits: &[Boolean]) -> Lc {
  let mut sum = Lc::zero();
  let mut weight = t256::Scalar::ONE;
  for bit in bits.iter().rev() {
    sum = sum + &Lc::bit(bit).scale(weight);
    weight = weight.double();
  }
  sum
}

/// Splits `x` into `n` bits with the range constraint of clause 5.2.3: one bit rule per bit and
/// one rule that reassembles `x`. The rules hold exactly when `x` is an integer below 2^n, which
/// needs 2^n below the field modulus.
pub fn bits<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  x: &Lc,
  n: usize,
) -> Result<Vec<Boolean>, SynthesisError> {
  assert!(n < t256::Scalar::NUM_BITS as usize, "2^n must stay below the field modulus");
  let value = x.value.map(|v| {
    let le = le_bits(&v);
    (0..n).rev().map(|i| le[i]).collect()
  });
  let bits = alloc_bits(cs.namespace(|| "bits"), value, n)?;
  equal(cs.namespace(|| "reassemble"), &pack(&bits), x);
  Ok(bits)
}

/// The 256 bits of a SHA-256 digest held as two 128-bit halves, high half first.
pub fn digest_bits<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  halves: &[Lc; 2],
) -> Result<Vec<Boolean>, SynthesisError> {
  let mut out = bits(cs.namespace(|| "high half"), &halves[0], 128)?;
  out.extend(bits(cs.namespace(|| "low half"), &halves[1], 128)?);
  Ok(out)
}

/// Adds the rules that `x` is an integer from 0 through 2^n − 1.
pub fn range_check<CS: ConstraintSystem<t256::Scalar>>(
  cs: CS,
  x: &Lc,
  n: usize,
) -> Result<(), SynthesisError> {
  bits(cs, x, n).map(|_| ())
}

/// Adds the rules that the integer with these bits is less than the constant `c`, given as
/// big-endian bytes of the same bit length.
///
/// The rules walk the bits from the top. `equal` is one while the bits agree with `c` so far.
/// The integer is smaller exactly when, at the first bit where they differ, `c` has a one and the
/// integer a zero. That event adds `equal − equal · bit` to `less` at a one of `c`, and the
/// events at different bits exclude each other. One rule per bit.
pub fn less_than<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  bits: &[Boolean],
  c: &[u8],
) -> Result<(), SynthesisError> {
  let c_bits = be_bits(c);
  assert_eq!(bits.len(), c_bits.len());
  let mut equal_so_far = Lc::constant(t256::Scalar::ONE);
  let mut less = Lc::zero();
  for (i, (bit, c_bit)) in bits.iter().zip(c_bits).enumerate() {
    let bit = Lc::bit(bit);
    let cs = &mut cs.namespace(|| format!("bit {i}"));
    if c_bit {
      let still = mul(cs.namespace(|| "agree at one"), &equal_so_far, &bit)?;
      less = less + &(&equal_so_far - &still);
      equal_so_far = still;
    } else {
      let not_bit = Lc::constant(t256::Scalar::ONE) - &bit;
      equal_so_far = mul(cs.namespace(|| "agree at zero"), &equal_so_far, &not_bit)?;
    }
  }
  equal(cs.namespace(|| "less"), &less, &Lc::constant(t256::Scalar::ONE));
  Ok(())
}

/// The values of [`less_than`] for the bits `bits`, computed natively: at each bit, whether the
/// bits so far agree with `c`'s, the product it allocates.
pub fn less_than_values(values: &mut Values, bits: &[bool], c: &[u8]) {
  let mut equal_so_far = true;
  for (&bit, c_bit) in bits.iter().zip(be_bits(c)) {
    equal_so_far &= bit == c_bit;
    values.bit(equal_so_far);
  }
}

/// The bytes of a bit list, eight bits per byte.
pub fn bytes(bits: &[Boolean]) -> Vec<Lc> {
  bits.chunks(8).map(pack).collect()
}

/// The big-endian integer of a byte list.
pub fn pack_bytes(bytes: &[Lc]) -> Lc {
  let mut sum = Lc::zero();
  let mut weight = t256::Scalar::ONE;
  for byte in bytes.iter().rev() {
    sum = sum + &byte.scale(weight);
    weight *= t256::Scalar::from(256);
  }
  sum
}

/// Adds the rules that bytes equal a constant string, sixteen bytes per rule. Each byte is
/// already restricted to 0..256, so a packed group of sixteen equals the packed constant only
/// when every byte does.
pub fn expect<CS: ConstraintSystem<t256::Scalar>>(mut cs: CS, bytes: &[Lc], pattern: &[u8]) {
  assert_eq!(bytes.len(), pattern.len());
  for (i, (group, constant)) in bytes.chunks(16).zip(pattern.chunks(16)).enumerate() {
    equal(
      cs.namespace(|| format!("bytes from {}", 16 * i)),
      &pack_bytes(group),
      &Lc::constant(from_be(constant)),
    );
  }
}

/// Adds the rules that bytes equal a constant string when the bit `flag` is one, sixteen bytes
/// per rule: flag · (packed bytes − packed constant) = 0.
pub fn expect_if<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  flag: &Lc,
  bytes: &[Lc],
  pattern: &[u8],
) {
  assert_eq!(bytes.len(), pattern.len());
  for (i, (group, constant)) in bytes.chunks(16).zip(pattern.chunks(16)).enumerate() {
    let difference = pack_bytes(group) - &Lc::constant(from_be(constant));
    product(cs.namespace(|| format!("bytes from {}", 16 * i)), flag, &difference, &Lc::zero());
  }
}

/// The number that a run of ASCII decimal digits writes. The issuer writes digits here, so no
/// rule is needed.
pub fn decimal(digits: &[Lc]) -> Lc {
  let mut sum = Lc::zero();
  let mut weight = t256::Scalar::ONE;
  for digit in digits.iter().rev() {
    sum = sum + &(digit - &Lc::small(u64::from(b'0'))).scale(weight);
    weight *= t256::Scalar::from(10);
  }
  sum
}
