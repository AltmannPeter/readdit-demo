//! Base64url text inside the rules (RFC 4648, clause 5, without padding).
//!
//! An SD-JWT carries its JSON base64url-encoded. The JWS signing input holds the encoded header
//! and payload, a disclosure is encoded JSON, and the digests the payload lists are encoded again
//! inside the JSON. The rules decode a window of characters into bits and reassemble the bytes.

use bellpepper_core::{
  ConstraintSystem, SynthesisError,
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
};
use ff::Field;
use vega_prover::provider::pt256::t256;

use super::bits::{alloc_bits, pack, range_check, small_bits};
use super::lc::{Lc, equal, mul, product, val};
use super::window::Message;
use crate::table::OFFSET_BITS;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The six-bit value of a base64url character.
pub fn value_of(c: u8) -> Option<u8> {
  ALPHABET.iter().position(|&a| a == c).map(|v| v as u8)
}

/// Encodes bytes as base64url without padding.
pub fn encode(bytes: &[u8]) -> String {
  let bits: Vec<bool> = super::bits::be_bits(bytes);
  bits
    .chunks(6)
    .map(|group| {
      let v =
        (0..6).fold(0usize, |v, i| 2 * v + usize::from(group.get(i).copied().unwrap_or(false)));
      ALPHABET[v] as char
    })
    .collect()
}

/// Decodes base64url text without padding.
pub fn decode(text: &[u8]) -> Option<Vec<u8>> {
  let mut bits = Vec::with_capacity(6 * text.len());
  for &c in text {
    bits.extend(small_bits(u64::from(value_of(c)?), 6));
  }
  let (bytes, _) = bits.as_chunks::<8>();
  Some(bytes.iter().map(|b| b.iter().fold(0u8, |v, &bit| 2 * v + u8::from(bit))).collect())
}

/// The bits that base64url characters encode, six per character.
///
/// The prover supplies each character's six-bit value v. One rule per character checks that v
/// is the character's value:
///
/// character = v + 65 + 6·[v ≥ 26] − 75·[v ≥ 52] − 13·[v ≥ 62] + 49·[v = 63].
///
/// The formula sends 0..26 to 'A'..'Z', 26..52 to 'a'..'z', 52..62 to '0'..'9', 62 to '-' and 63
/// to '_', and it is one-to-one, so the character fixes v. The four flags are products of the
/// bits, built along one chain of prefixes: m = b5·b4 (v ≥ 48), then each further bit extends the
/// chain. The flag v ≥ 52 needs no product of its own: [v ≥ 52] = m·(b3 ∨ b2), and the
/// inclusion-exclusion m·(b3 ∨ b2) = m·b3 + m·b2 − m·b3·b2 reuses the chain's m·b3 and m·b3·b2.
/// That is ten products per character, where a rule per Boolean connective needed eleven.
///
/// A witness generator, which ignores the rules, takes the products natively.
pub fn decode_chars<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  chars: &[Lc],
) -> Result<Vec<Boolean>, SynthesisError> {
  if cs.is_witness_generator() {
    return decode_values(cs, chars);
  }
  let mut out = Vec::with_capacity(6 * chars.len());
  for (i, c) in chars.iter().enumerate() {
    let cs = &mut cs.namespace(|| format!("character {i}"));
    // A byte that is not a base64url character has no value; zero makes the rule fail.
    let v = c.value.map(|c| {
      let byte = super::lc::to_be(&c)[31];
      small_bits(u64::from(value_of(byte).unwrap_or(0)), 6)
    });
    let b = alloc_bits(cs.namespace(|| "value"), v, 6)?;
    let (b5, b4, b3, b2, b1, b0) = (&b[0], &b[1], &b[2], &b[3], &b[4], &b[5]);
    let bit = |x: &Boolean| Lc::bit(x);
    // The chain of prefixes: m = b5·b4 (v ≥ 48), ge56 = m·b3, ge60 = ge56·b2, ge62 = ge60·b1.
    let m = mul(cs.namespace(|| "b5 and b4"), &bit(b5), &bit(b4))?;
    let ge56 = mul(cs.namespace(|| "v >= 56"), &m, &bit(b3))?;
    let ge60 = mul(cs.namespace(|| "v >= 60"), &ge56, &bit(b2))?;
    let ge62 = mul(cs.namespace(|| "v >= 62"), &ge60, &bit(b1))?;
    let eq63 = mul(cs.namespace(|| "v = 63"), &ge62, &bit(b0))?;
    // [v ≥ 52] = m·b3 + m·b2 − m·b3·b2, with m·b2 the one new product.
    let m_b2 = mul(cs.namespace(|| "b5, b4 and b2"), &m, &bit(b2))?;
    let ge52 = &ge56 + &m_b2 - &ge60;
    // [v ≥ 26] = b5 + (1 − b5)·b4·b3·(b2 ∨ b1), with b2 ∨ b1 = b2 + b1 − b2·b1. The factor
    // 1 − b5 makes the second term vanish when b5 is one, where the first term already gives one.
    let b2_b1 = mul(cs.namespace(|| "b2 and b1"), &bit(b2), &bit(b1))?;
    let b2_or_b1 = bit(b2) + &bit(b1) - &b2_b1;
    let b4_b3 = mul(cs.namespace(|| "b4 and b3"), &bit(b4), &bit(b3))?;
    let below32 = Lc::small(1) - &bit(b5);
    let b4_b3_below32 = mul(cs.namespace(|| "b4, b3 below 32"), &b4_b3, &below32)?;
    let from26 = mul(cs.namespace(|| "26..32"), &b4_b3_below32, &b2_or_b1)?;
    let ge26 = bit(b5) + &from26;
    #[rustfmt::skip]
    let character = pack(&b)
      + &Lc::small(65)
      + &ge26.scale(t256::Scalar::from(6))
      - &ge52.scale(t256::Scalar::from(75))
      - &ge62.scale(t256::Scalar::from(13))
      + &eq63.scale(t256::Scalar::from(49));
    equal(cs.namespace(|| "character"), &character, c);
    out.extend(b);
  }
  Ok(out)
}

/// The values of [`decode_chars`], computed natively for a witness generator, in its order: for
/// each character its six bits, allocated as bits, which it returns, and its ten products.
fn decode_values<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  chars: &[Lc],
) -> Result<Vec<Boolean>, SynthesisError> {
  let mut out = Vec::with_capacity(6 * chars.len());
  for c in chars {
    let byte = super::lc::to_be(&c.value.ok_or(SynthesisError::AssignmentMissing)?)[31];
    let b = small_bits(u64::from(value_of(byte).unwrap_or(0)), 6);
    for &bit in &b {
      out.push(Boolean::from(AllocatedBit::alloc(&mut cs, Some(bit))?));
    }
    let (b5, b4, b3, b2, b1, b0) = (b[0], b[1], b[2], b[3], b[4], b[5]);
    let m = b5 && b4;
    let b4_b3_below32 = b4 && b3 && !b5;
    let products = [
      m,
      m && b3,
      m && b3 && b2,
      m && b3 && b2 && b1,
      m && b3 && b2 && b1 && b0,
      m && b2,
      b2 && b1,
      b4 && b3,
      b4_b3_below32,
      b4_b3_below32 && (b2 || b1),
    ];
    cs.extend_aux(&products.map(|p| if p { t256::Scalar::ONE } else { t256::Scalar::ZERO }));
  }
  Ok(out)
}

/// JSON text that a message holds base64url-encoded, starting at a message offset.
pub struct EncodedText<'a> {
  pub message: &'a Message<'a>,
  /// The message offset of the first character, as a sum of slots and as the prover knows it.
  pub start: Lc,
  pub start_hint: Option<usize>,
}

impl EncodedText<'_> {
  /// Reads `len` bytes of the decoded text, as the slots of [`EncodedText::read_slots`].
  pub fn read<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: CS,
    at: Option<usize>,
    len: usize,
  ) -> Result<Vec<Lc>, SynthesisError> {
    Ok(self.read_slots(cs, at, len)?.iter().map(Lc::num).collect())
  }

  /// Reads `len` bytes of the decoded text, starting at the private decoded offset `at`.
  ///
  /// Decoded byte t begins at bit 8t of the text's bit stream, which is bit β = 8t mod 6 of
  /// character ⌊8t/6⌋, with β one of 0, 2 or 4. The rules read the characters from there, decode
  /// them, and assemble the bytes starting β bits in. An alignment rule ties the character offset
  /// to t, so the bytes always start on a byte boundary of the decoded text. The window takes
  /// ⌊(8·len + 3)/6⌋ + 1 characters, which reaches at most one character past the last byte read.
  /// Every field read here is followed by more JSON, so that character exists.
  ///
  /// Each byte is a slot of its own, defined by two rules: the choice between the candidates at
  /// β = 2 is one product, and the byte equals the first candidate plus that choice plus the
  /// choice at β = 4, which is the second product. The byte's slot is the second product's
  /// output, so the slot needs no rule of its own.
  ///
  /// A witness generator, which ignores the rules, takes the bytes' values natively.
  pub fn read_slots<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    mut cs: CS,
    at: Option<usize>,
    len: usize,
  ) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
    let chars = (8 * len + 3) / 6 + 1;
    let char_at = at.zip(self.start_hint).map(|(t, start)| start + 8 * t / 6);
    let window = self.message.read(cs.namespace(|| "characters"), char_at, chars)?;

    let beta = at.map(|t| 8 * t % 6);
    let flags = alloc_bits(cs.namespace(|| "alignment"), beta.map(|b| vec![b == 2, b == 4]), 2)?;
    let (two, four) = (Lc::bit(&flags[0]), Lc::bit(&flags[1]));
    product(cs.namespace(|| "one alignment"), &two, &four, &Lc::zero());

    // 6 · (character offset) + β = 8 · t, with t a small integer.
    let t = Lc::alloc(cs.namespace(|| "decoded offset"), at.map(|t| t256::Scalar::from(t as u64)))?;
    range_check(cs.namespace(|| "decoded offset range"), &t, OFFSET_BITS)?;
    if cs.is_witness_generator() {
      let bits = decode_chars(cs.namespace(|| "decode"), &window.bytes)?;
      return Self::byte_values(cs, &bits, [&flags[0], &flags[1]], len);
    }
    let bit_offset = (&window.offset - &self.start).scale(t256::Scalar::from(6))
      + &two.scale(t256::Scalar::from(2))
      + &four.scale(t256::Scalar::from(4));
    equal(cs.namespace(|| "byte boundary"), &bit_offset, &t.scale(t256::Scalar::from(8)));

    let bits = decode_chars(cs.namespace(|| "decode"), &window.bytes)?;
    (0..len)
      .map(|k| {
        let candidate = |shift: usize| pack(&bits[shift + 8 * k..shift + 8 * k + 8]);
        let (at0, at2, at4) = (candidate(0), candidate(2), candidate(4));
        let cs = &mut cs.namespace(|| format!("byte {k}"));
        let from2 = mul(cs.namespace(|| "at 2"), &two, &(&at2 - &at0))?;
        let value = val([at0.value, from2.value, four.value, at4.value], |[a0, f2, f4, a4]| {
          a0 + f2 + f4 * (a4 - a0)
        });
        let byte = AllocatedNum::alloc(cs.namespace(|| "value"), || {
          value.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let rest = Lc::num(&byte) - &at0 - &from2;
        product(cs.namespace(|| "at 4"), &four, &(&at4 - &at0), &rest);
        Ok(byte)
      })
      .collect()
  }

  /// The values of [`EncodedText::read_slots`]'s bytes, computed natively for a witness
  /// generator from the decoded bits `bits` and the alignment flags (β = 2, β = 4), in its order:
  /// for each byte the choice at β = 2 and the byte's slot, which it returns.
  fn byte_values<CS: ConstraintSystem<t256::Scalar>>(
    mut cs: CS,
    bits: &[Boolean],
    flags: [&Boolean; 2],
    len: usize,
  ) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
    let missing = || SynthesisError::AssignmentMissing;
    let bits =
      bits.iter().map(Boolean::get_value).collect::<Option<Vec<bool>>>().ok_or_else(missing)?;
    let [two, four] = flags.map(Boolean::get_value);
    let (two, four) = (two.ok_or_else(missing)?, four.ok_or_else(missing)?);
    (0..len)
      .map(|k| {
        let candidate = |shift: usize| {
          let byte = bits[shift + 8 * k..shift + 8 * k + 8].iter();
          t256::Scalar::from(byte.fold(0u64, |v, &bit| 2 * v + u64::from(bit)))
        };
        let (at0, at2, at4) = (candidate(0), candidate(2), candidate(4));
        let from2 = if two { at2 - at0 } else { t256::Scalar::ZERO };
        cs.alloc(|| "at 2", || Ok(from2))?;
        let byte = at0 + from2 + if four { at4 - at0 } else { t256::Scalar::ZERO };
        AllocatedNum::alloc(&mut cs, || Ok(byte))
      })
      .collect()
  }
}
