//! The pseudonym of the full nym_auth statement: `pseudonym-v1-sha256` in its configuration
//! `known-offender-matching-ssc` (the nym_auth rulebook, "Pseudonym generation function").
//!
//! The credential carries `ssc` = SHA-256(secret_seed), an attribute the issuer signs like the
//! birth date: the mdoc element `ssc`, a byte string of 32 bytes, and the SD-JWT VC claim `ssc`,
//! those bytes as 64 lowercase hex digits. The holder keeps the 16-byte secret_seed, which the
//! issuer shares, next to the credential; it is a private input. The pseudonym, a public output,
//! is SHA-256(DST ‖ secret_seed ‖ prover_input ‖ verifier_input), with DST
//! `nym_auth/v1/known-offender-matching-ssc`, prover_input 32 zero bytes and verifier_input the
//! SHA-256 of the verifier's client_id, which the verifier computes and names as a public value.
//!
//! The rules add to the age statement ([`crate::mdoc::MdocNymCore`],
//! [`crate::sdjwt::SdJwtNymCore`]), in the table's layout [`crate::table::FULL_MDOC`] or
//! [`crate::table::FULL_SD_JWT`]:
//!
//! | Rule | What the prover could otherwise do |
//! | --- | --- |
//! | The signed message lists the `ssc` attribute's digest | Use an `ssc` the issuer never signed |
//! | The attribute's name is `ssc`, and its value a 32-byte string (mdoc) or 64 hex digits (SD-JWT) | Pass another attribute off as `ssc` |
//! | Each SD-JWT digit is `0`–`9` or `a`–`f`, and decodes to its nibble ([`hex_bytes`]) | Decode the claim into other bytes |
//! | The seed's message is the secret seed, padded, and its digest is `ssc`'s value | Use a seed that does not open `ssc` |
//! | The pseudonym's message is DST, that seed, 32 zero bytes and the verifier's verifier_input, padded | Present another verifier's pseudonym, or one of another seed |
//! | The pseudonym is that message's digest | Pick the pseudonym |
//!
//! The step instances check the three messages' compressions, from the SHA-256 initial value: the
//! attribute's blocks, the seed's one and the pseudonym's two. The core reads the attribute as
//! the age statement reads the birth date, and the seed's and the pseudonym's blocks at their
//! fixed positions. The seed sits in the seed's first chunk and, split at its ninth byte, in the
//! pseudonym's first block's last two chunks: a range check of 56 bits on its low seven bytes, and
//! the steps' 128-bit range checks of every chunk, make the split exact. Everything but the
//! verifier's values is fixed for a credential and goes in the precommitted segment; the rest
//! segment compares the pseudonym's second block, which holds verifier_input, and its digest with
//! the public values, through five slots.
//!
//! **The prepared state.** The table holds the pseudonym's blocks, and the pseudonym's second
//! block holds verifier_input, so a state prepared once serves the presentations to one verifier:
//! the holder prepares once per credential and verifier.
//!
//! **The public values** add five to the age statement's, after the request's: verifier_input in
//! three values split where its bytes cross the table's chunks (bytes 0 to 8, 9 to 24 and 25 to
//! 31, so the rules compare them linearly), and the pseudonym's two 128-bit halves. The proof
//! carries the core's public values, and the verifier reads the pseudonym there
//! ([`crate::app::accept_pseudonym`]): beyond the values the verifier names, the pseudonym is
//! the one value the proof reveals.

use bellpepper_core::{ConstraintSystem, SynthesisError, num::AllocatedNum};
use vega_prover::provider::pt256::t256;

use crate::gadgets::bits::{alloc_bits, pack, small_bits};
use crate::gadgets::lc::{Lc, equal, from_be, inverse, mul, product, to_be, to_num};
use crate::gadgets::window::find;
use crate::table::{CHUNKS_PER_BLOCK, Cells, PseudonymRegions, Region, sha256};

/// The function and its configuration.
pub const FUNCTION: &str = "pseudonym-v1-sha256";
pub const CONFIG: &str = "known-offender-matching-ssc";

/// The configuration's domain separation tag, `nym_auth/v1/<config>`.
pub const DST: &[u8] = b"nym_auth/v1/known-offender-matching-ssc";

/// The configuration's prover_input: null, 32 zero bytes.
pub const PROVER_INPUT: [u8; 32] = [0; 32];

/// The secret seed's bytes, and the commitment's.
pub const SEED_BYTES: usize = 16;
pub const SSC_BYTES: usize = 32;

/// The mdoc item's key elementIdentifier and the 3-byte text `ssc`.
pub const MDOC_IDENTIFIER: &[u8] = b"\x71elementIdentifier\x63ssc";

/// The mdoc item's key elementValue and the head of a 32-byte string.
pub const MDOC_VALUE: &[u8] = b"\x6celementValue\x58\x20";

/// The SD-JWT disclosure's claim name `ssc` with its quotes and the comma after it.
pub const SD_JWT_CLAIM: &[u8] = b"\"ssc\",";

/// The SD-JWT claim's hex digits.
pub const HEX_DIGITS: usize = 2 * SSC_BYTES;

/// The public values the pseudonym adds to the core's: verifier_input's three, the pseudonym's
/// two.
pub const VALUES: usize = 5;

/// A verifier's verifier_input: the SHA-256 of its client_id.
pub fn verifier_input(client_id: &str) -> [u8; 32] {
  sha256(client_id.as_bytes())
}

/// The pseudonym's message, 119 bytes: DST, the seed, prover_input and verifier_input.
pub fn message(seed: &[u8; 16], verifier_input: &[u8; 32]) -> Vec<u8> {
  [DST, seed, &PROVER_INPUT, verifier_input].concat()
}

/// The pseudonym of `seed` for `verifier_input`.
pub fn pseudonym(seed: &[u8; 16], verifier_input: &[u8; 32]) -> [u8; 32] {
  sha256(&message(seed, verifier_input))
}

/// The nibble of a hex digit as the rules decode it ([`hex_bytes`]): its low four bits, plus 9
/// when the byte's bit 6 is set. That is a lowercase digit's value; on any other byte the prover
/// still has a nibble, and the rules refuse the byte.
pub fn nibble(digit: u8) -> u8 {
  ((digit & 0x0f) + 9 * ((digit >> 6) & 1)) & 0x0f
}

/// The offset of `"ssc",` in the decoded SD-JWT disclosure `claim`, and whether a space follows
/// the comma.
pub fn claim_at(claim: &[u8]) -> Result<(usize, bool), String> {
  let at = find(claim, SD_JWT_CLAIM, "the ssc claim name")?;
  Ok((at, claim.get(at + SD_JWT_CLAIM.len()) == Some(&b' ')))
}

/// What the prover adds to the credential for the full statement: the `ssc` attribute (the
/// mdoc's IssuerSignedItemBytes or the SD-JWT's disclosure), the holder's secret seed and the
/// verifier's verifier_input.
#[derive(Clone, Copy, Debug)]
pub struct NymMessages<'a> {
  pub ssc: &'a [u8],
  pub secret_seed: &'a [u8; 16],
  pub verifier_input: &'a [u8; 32],
}

impl NymMessages<'_> {
  /// The three messages the table holds besides the signed one and the birth date's attribute,
  /// in their regions: the `ssc` attribute, the secret seed and the pseudonym's message.
  pub fn table_messages(&self, regions: &PseudonymRegions) -> [(Region, Vec<u8>); 3] {
    [
      (regions.ssc, self.ssc.to_vec()),
      (regions.seed, self.secret_seed.to_vec()),
      (regions.nym, message(self.secret_seed, self.verifier_input)),
    ]
  }
}

/// The verifier's values of the pseudonym: the verifier_input it names, and the pseudonym the
/// proof reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NymPublic {
  pub verifier_input: [u8; 32],
  pub pseudonym: [u8; 32],
}

impl NymPublic {
  /// verifier_input's three public values: its bytes 0 to 8, 9 to 24 and 25 to 31.
  pub fn verifier_values(verifier_input: &[u8; 32]) -> [t256::Scalar; 3] {
    [from_be(&verifier_input[..9]), from_be(&verifier_input[9..25]), from_be(&verifier_input[25..])]
  }

  /// The five public values, after the age statement's: verifier_input's three, then the
  /// pseudonym's halves.
  pub fn values(&self) -> Vec<t256::Scalar> {
    let mut values = Self::verifier_values(&self.verifier_input).to_vec();
    values.extend([from_be(&self.pseudonym[..16]), from_be(&self.pseudonym[16..])]);
    values
  }
}

/// The pseudonym from the last two of a core's public values, its halves, each below 2^128.
pub fn pseudonym_of(values: &[t256::Scalar]) -> Option<[u8; 32]> {
  let [.., high, low] = values else {
    return None;
  };
  let (high, low) = (to_be(high), to_be(low));
  if high[..16].iter().chain(&low[..16]).any(|&b| b != 0) {
    return None;
  }
  let mut out = [0u8; 32];
  out[..16].copy_from_slice(&high[16..]);
  out[16..].copy_from_slice(&low[16..]);
  Some(out)
}

/// 2^72, the weight of a chunk's byte 7 (counted from 0 at the top).
fn two_72() -> t256::Scalar {
  t256::Scalar::from(1u64 << 36).square()
}

/// The constant of a chunk's bytes.
fn constant(bytes: &[u8]) -> Lc {
  Lc::constant(from_be(bytes))
}

/// The value the pseudonym's last chunk adds to verifier_input's last seven bytes there: the byte
/// 0x80 of SHA-256's padding and the message's 952 bits as a 64-bit number.
fn last_chunk_padding() -> t256::Scalar {
  let mut bytes = [0u8; 9];
  bytes[0] = 0x80;
  bytes[1..].copy_from_slice(&(8 * 119u64).to_be_bytes());
  from_be(&bytes)
}

/// The bytes of 64 hex digits, each digit a byte slot of the SD-JWT disclosure's decoded text.
///
/// Each digit c gets its nibble n as four bits and the letter flag L = n₃ · (n₂ ∨ n₁), which is
/// one when n is 10 or more, and the rule c = 0x30 + n + 0x27 · L. With L zero, n is at most 9
/// and c is `0`–`9`; with L one, n is 10 to 15 and c is `a`–`f`. Every other byte, uppercase
/// digits among them, has no such n, so the rules refuse it, and a lowercase digit has one n
/// only, its value. Six rules per digit: the four bits, n₂ · n₁, and L's product, which carries
/// the equation (c − 0x30 − n) / 0x27 = n₃ · (n₂ + n₁ − n₂ · n₁). Byte k is 16 n₂ₖ + n₂ₖ₊₁.
pub fn hex_bytes<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  digits: &[Lc],
) -> Result<Vec<Lc>, SynthesisError> {
  assert_eq!(digits.len(), HEX_DIGITS);
  let letter = inverse(t256::Scalar::from(0x27u64));
  let mut nibbles = Vec::with_capacity(HEX_DIGITS);
  for (i, c) in digits.iter().enumerate() {
    let cs = &mut cs.namespace(|| format!("ssc digit {i}"));
    let n = c.value.map(|v| small_bits(u64::from(nibble(to_be(&v)[31])), 4));
    let b = alloc_bits(cs.namespace(|| "nibble"), n, 4)?;
    let (b3, b2, b1) = (Lc::bit(&b[0]), Lc::bit(&b[1]), Lc::bit(&b[2]));
    let b2_b1 = mul(cs.namespace(|| "n2 and n1"), &b2, &b1)?;
    let n = pack(&b);
    let flag = (c - &Lc::small(0x30) - &n).scale(letter);
    product(cs.namespace(|| "letter"), &b3, &(b2 + &b1 - &b2_b1), &flag);
    nibbles.push(n);
  }
  Ok(nibbles.chunks(2).map(|pair| pair[0].scale(t256::Scalar::from(16)) + &pair[1]).collect())
}

/// The rules of the seed's and the pseudonym's messages at their fixed positions (module
/// documentation). Returns the seed's digest, the state after its block, as two 128-bit halves,
/// and the five values the rest segment compares with the public values: the pseudonym's second
/// block's last three chunks and the state after it.
pub fn seed_and_nym<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  cells: &Cells,
  regions: &PseudonymRegions,
) -> Result<([Lc; 2], [Lc; VALUES]), SynthesisError> {
  let chunk = |j: usize, c: usize| cells.chunk(CHUNKS_PER_BLOCK * j + c);

  // The seed's message: the seed, then the padding of a 16-byte message.
  let s = regions.seed.first;
  let seed = chunk(s, 0);
  let mut padding = [[0u8; 16]; 3];
  padding[0][0] = 0x80;
  padding[2][15] = 0x80;
  for (c, bytes) in padding.iter().enumerate() {
    equal(cs.namespace(|| format!("seed padding {}", c + 1)), &chunk(s, c + 1), &constant(bytes));
  }
  let digest = [cells.state(s, 0), cells.state(s, 1)];

  // The pseudonym's first block: DST's 39 bytes, the seed's 16, and prover_input's first 9 zero
  // bytes. The seed's low 7 bytes, a 56-bit number, fill the last chunk's top; its high 9 bytes
  // end the chunk before it, after DST's last 7.
  let n = regions.nym.first;
  equal(cs.namespace(|| "pseudonym dst 0"), &chunk(n, 0), &constant(&DST[..16]));
  equal(cs.namespace(|| "pseudonym dst 1"), &chunk(n, 1), &constant(&DST[16..32]));
  let low = seed.value.map(|v| {
    let be = to_be(&v);
    let mut word = [0u8; 8];
    word[1..].copy_from_slice(&be[25..]);
    small_bits(u64::from_be_bytes(word), 56)
  });
  let low = pack(&alloc_bits(cs.namespace(|| "seed low bytes"), low, 56)?);
  let two_72 = two_72();
  equal(cs.namespace(|| "pseudonym seed low"), &chunk(n, 3), &low.scale(two_72));
  let high = (&seed - &low).scale(inverse(t256::Scalar::from(1u64 << 56)));
  let dst_end = Lc::constant(from_be(&DST[32..]) * two_72);
  equal(cs.namespace(|| "pseudonym seed high"), &chunk(n, 2), &(dst_end + &high));

  // The pseudonym's second block: prover_input's next 16 zero bytes, then what the rest segment
  // compares with verifier_input.
  equal(cs.namespace(|| "pseudonym prover input"), &chunk(n + 1, 0), &Lc::zero());
  let facts = [
    chunk(n + 1, 1),
    chunk(n + 1, 2),
    chunk(n + 1, 3),
    cells.state(n + 1, 0),
    cells.state(n + 1, 1),
  ];
  Ok((digest, facts))
}

/// The commitment's rule ([`seed_and_nym`]'s digest against `ssc`'s value, its two 128-bit
/// halves), then the five values of the pseudonym in slots, which the rest segment reads.
pub fn commitment_and_slots<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  cells: &Cells,
  regions: &PseudonymRegions,
  ssc: &[Lc; 2],
) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
  let (seed_digest, facts) = seed_and_nym(cs.namespace(|| "seed and pseudonym"), cells, regions)?;
  for (h, (seed_half, ssc_half)) in seed_digest.iter().zip(ssc).enumerate() {
    equal(cs.namespace(|| format!("seed digest half {h} is ssc")), seed_half, ssc_half);
  }
  into_slots(cs.namespace(|| "facts"), &facts)
}

/// The five values of [`seed_and_nym`] in slots, which the rest segment reads.
pub fn into_slots<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  facts: &[Lc; VALUES],
) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
  let names = ["verifier input high", "verifier input middle", "verifier input low"];
  let names = names.into_iter().chain(["pseudonym high", "pseudonym low"]);
  names.zip(facts).map(|(name, fact)| to_num(cs.namespace(|| name), fact)).collect()
}

/// The rest segment's rules of the pseudonym: the five public values after the age statement's,
/// and the slots of [`into_slots`] equal to them, verifier_input's last bytes beside the padding.
pub fn check<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  facts: &[AllocatedNum<t256::Scalar>],
  nym: Option<&NymPublic>,
) -> Result<(), SynthesisError> {
  let values = nym.map(NymPublic::values);
  let names = ["verifier input high", "verifier input middle", "verifier input low"];
  let names: Vec<&str> = names.into_iter().chain(["pseudonym high", "pseudonym low"]).collect();
  let public = names
    .iter()
    .enumerate()
    .map(|(i, name)| {
      let value = values.as_ref().map(|v| v[i]);
      let input = AllocatedNum::alloc_input(cs.namespace(|| format!("public {name}")), || {
        value.ok_or(SynthesisError::AssignmentMissing)
      })?;
      Ok(Lc::num(&input))
    })
    .collect::<Result<Vec<_>, SynthesisError>>()?;
  if facts.len() != VALUES {
    return Err(SynthesisError::AssignmentMissing);
  }
  let padded = public[2].scale(two_72()) + &Lc::constant(last_chunk_padding());
  let expected =
    [public[0].clone(), public[1].clone(), padded, public[3].clone(), public[4].clone()];
  for ((name, fact), expected) in names.iter().zip(facts).zip(&expected) {
    equal(cs.namespace(|| *name), &Lc::num(fact), expected);
  }
  Ok(())
}

// The message fills exactly two blocks once padded: 119 bytes, the byte 0x80 and the length.
const _: () = assert!(DST.len() + 16 + 32 + 32 == 119);
// DST's last 7 bytes and the seed's first 9 fill the third chunk.
const _: () = assert!(DST.len() == 32 + 7);
