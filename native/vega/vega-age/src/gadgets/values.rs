//! A circuit's values in the order a witness generator records them, computed natively.
//!
//! The prover takes the values of a circuit from its witness generator, `SatisfyingAssignment`,
//! which ignores the rules and records each allocated value in turn. Where synthesizing a gadget
//! costs far more than its values, the crate computes those values directly, in the gadget's order
//! and with the gadget's values: the step circuit ([`crate::step::Step::assignment`], which mirrors
//! bellpepper's SHA-256 compression in [`super::sha256`]), and the ECDSA verifications, the windows
//! and the base64url decoding of the cores (the witness branches of [`super::p256::verify`],
//! [`super::window::Message::read`], [`super::base64::decode_chars`] and
//! [`super::base64::EncodedText::read_slots`]). The rules stay the gadgets' own: every other
//! constraint system builds them, and [`crate::app::first_broken`] checks an assignment against
//! them.

use ff::{Field, PrimeField};
use vega_prover::provider::pt256::t256;

/// Values in allocation order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Values(pub Vec<t256::Scalar>);

impl Values {
  pub fn with_capacity(capacity: usize) -> Self {
    Values(Vec::with_capacity(capacity))
  }

  pub fn push(&mut self, value: t256::Scalar) {
    self.0.push(value);
  }

  /// A bit, as one or zero.
  pub fn bit(&mut self, bit: bool) {
    self.0.push(if bit { t256::Scalar::ONE } else { t256::Scalar::ZERO });
  }

  /// Bits in their order.
  pub fn bits(&mut self, bits: &[bool]) {
    self.0.extend(bits.iter().map(|&b| if b { t256::Scalar::ONE } else { t256::Scalar::ZERO }));
  }

  /// The `n` low bits of `v`, least significant first, as bellpepper's `UInt32` allocates a sum.
  pub fn low_bits(&mut self, v: u64, n: usize) {
    self.0.extend(
      (0..n).map(|i| if (v >> i) & 1 == 1 { t256::Scalar::ONE } else { t256::Scalar::ZERO }),
    );
  }

  /// The bits of bytes, most significant first, as [`super::bits::bits`] splits the integer they
  /// write.
  pub fn byte_bits(&mut self, bytes: &[u8]) {
    for byte in bytes {
      self.0.extend(
        (0..8).rev().map(
          |i| {
            if (byte >> i) & 1 == 1 { t256::Scalar::ONE } else { t256::Scalar::ZERO }
          },
        ),
      );
    }
  }

  /// The `n` low bits of a field element's integer, most significant first, as
  /// [`super::bits::bits`] splits it.
  pub fn field_bits(&mut self, x: &t256::Scalar, n: usize) {
    let repr = x.to_repr();
    let le = repr.as_ref();
    self.0.extend((0..n).rev().map(|i| {
      if (le[i / 8] >> (i % 8)) & 1 == 1 { t256::Scalar::ONE } else { t256::Scalar::ZERO }
    }));
  }
}
