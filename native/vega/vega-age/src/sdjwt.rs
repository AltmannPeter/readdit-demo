//! The core circuit for an SD-JWT VC (RFC 9901).
//!
//! The issuer signs a JWS (RFC 7515). Its signing input is the base64url-encoded header, a
//! period, and the base64url-encoded payload. The payload lists the digest of each disclosure in
//! `_sd` and holds the device key in `cnf.jwk`. A disclosure is the base64url encoding of a JSON
//! array of a salt, a claim name and a claim value. Its digest is the SHA-256 digest of that
//! encoding, and the payload lists the digest base64url-encoded. The shared table holds the
//! signing input and the disclosure of the birth date.
//!
//! The payload may state the start of validity in `nbf` and its end in `exp`. SD-JWT VC makes
//! both claims optional and forbids disclosing them selectively. A credential without nbf is
//! valid from its issuance, and one without exp does not expire.
//!
//! The rules check what a dishonest prover could fake, as for an mdoc.
//!
//! | Rule | What the prover could otherwise do |
//! | --- | --- |
//! | The issuer signed the signing input | Invent or alter a credential |
//! | The payload's vct is the one the verifier names | Use another credential of the same issuer |
//! | The payload lists the disclosure's digest | Use a disclosure the issuer never signed |
//! | The disclosure's claim name is the one the verifier names | Pass another claim off as the birth date |
//! | The device key, nbf and exp come from the payload | Pick them |
//! | A payload said to lack nbf or exp holds no such key | Drop the start or the end of validity |
//! | Every read ends within the message's last block | Read bytes placed after the message |
//!
//! The rules do not parse JSON. They decode base64url where they read, and the trusted issuer
//! writes each key name below once. Each of these key names holds a quote. JSON escapes every quote
//! inside a text, and base64url, in which the payload writes the device key, has none. A holder
//! therefore cannot plant a key name in bytes it chooses. The disclosure's digest is the exception,
//! because the payload holds other 43-character strings. The device key's coordinates are such
//! strings, and the device signature stops a holder who asked for a device key whose coordinate is
//! the digest of a forged disclosure.
//!
//! The vct and the claim name are the verifier's patterns ([`crate::request`]). The vct's window
//! starts at its key and reaches 40 bytes past the longest vct, so the payload holds at least
//! 41 − n decoded bytes after the closing quote of a vct of n bytes; the claims an issuer writes
//! after the vct give them. The claim name's window ends at the comma after the name, and the
//! birth date follows it. The window starts 16 − n bytes before a name of n bytes. The disclosure
//! holds 27 bytes before the name, `["`, a salt of 128 bits as 22 base64url characters, and `","`,
//! so the window starts inside the disclosure for every name of at most 16 bytes.
//!
//! A read shows where a key is, but not that a key is missing. The prover therefore states in two
//! private table entries whether the payload lacks nbf and whether it lacks exp. For a missing
//! key the core reads no time, and every step instance checks that its block holds no occurrence
//! of the key ([`scan`]). The proof has the same shape either way, so it does not reveal which
//! claims the credential has.

use std::sync::Arc;

use bellpepper_core::{ConstraintSystem, SynthesisError, num::AllocatedNum};
use vega_prover::traits::circuit::VegaCircuit;

use bellpepper_core::boolean::Boolean;
use ff::Field;
use vega_prover::provider::{T256HyraxEngine, pt256::t256};

use crate::app::Core;
use crate::gadgets::base64::{self, EncodedText, decode_chars};
use crate::gadgets::bits::{
  alloc_bits, bits, bytes, decimal, digest_bits, expect, expect_if, pack, pack_bytes, range_check,
};
use crate::gadgets::lc::{
  Lc, equal, from_be, inverse_all, low_bytes, mul, mux, nonzero_if, product, to_num,
};
use crate::gadgets::p256::{Point, PublicKey, Signature, verify};
use crate::gadgets::select::{OneHot, select_values};
use crate::gadgets::values::Values;
use crate::gadgets::window::{Message, find};
use crate::presentation::{
  self, BASE_VALUES, DATE_DIGITS, Facts, NO_END, Presentation, TimeEncoding,
};
use crate::pseudonym::{self, HEX_DIGITS, NymPublic, SD_JWT_CLAIM};
use crate::request::{CLAIM_WINDOW, VCT_WINDOW, Window};
use crate::table::{
  self, AGE, CHUNKS_PER_BLOCK, Cells, FULL_SD_JWT, Layout, OFFSET_BITS, Region, Scan, Table,
  blocks_before, last_block, sha256,
};

pub use crate::request::VCT_KEY as TYPE_KEY;

/// The windows of an SD-JWT request: the vct and the claim name.
pub const WINDOWS: [Window; 2] = [VCT_WINDOW, CLAIM_WINDOW];

/// The bytes after the claim name's window that the rules read: a quote and the date's ten, or a
/// space, a quote and the date's first nine.
const AFTER_CLAIM: usize = 12;

/// The key nbf. Ten digits follow it for the times from 2001 to 2286.
pub const NOT_BEFORE: &[u8] = b"\"nbf\":";

/// The key exp. Ten digits follow it, as for nbf.
pub const EXPIRY: &[u8] = b"\"exp\":";

/// An alignment of a key in base64url text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Alignment {
  /// The phase of the key's first whole character in the payload's text, modulo 4.
  pub phase: usize,
  /// The key's whole characters.
  pub characters: &'static [u8],
}

/// A key and its three alignments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeKey {
  pub key: &'static [u8],
  pub alignments: [Alignment; 3],
}

const fn aligned(phase: usize, characters: &'static [u8]) -> Alignment {
  Alignment { phase, characters }
}

/// The optional time keys, nbf and exp, each with its whole base64url characters in the
/// payload's text.
///
/// Base64url writes three bytes as four characters, so a byte of the decoded payload starts at
/// bit 0 of a character's six bits, or at bit 2 or bit 4. Each start is an alignment of the key.
/// At bit 0 the key's six bytes fill eight characters. At bit 2 or 4 the key fills seven
/// characters, and shares a character with the bytes on each side. Each alignment lists the
/// phase of its first whole character in the payload's text, counted modulo 4, and its whole
/// characters.
pub const TIMES: [TimeKey; 2] = [
  TimeKey {
    key: NOT_BEFORE,
    alignments: [aligned(0, b"Im5iZiI6"), aligned(2, b"JuYmYiO"), aligned(3, b"ibmJmIj")],
  },
  TimeKey {
    key: EXPIRY,
    alignments: [aligned(0, b"ImV4cCI6"), aligned(2, b"JleHAiO"), aligned(3, b"iZXhwIj")],
  },
];

/// The key x of the JWK and the opening quote of its value.
pub const DEVICE_KEY_X: &[u8] = b"\"x\":\"";

/// The end of x and the key y, which follows it.
pub const DEVICE_KEY_Y: &[u8] = b"\",\"y\":\"";

/// The length of a 32-byte value in base64url.
const ENCODED_32: usize = 43;

/// What the prover knows about the credential.
#[derive(Clone, Debug)]
pub struct SdJwtWitness {
  pub table: Arc<Table>,
  pub issuer_key: PublicKey,
  pub issuer_signature: Signature,
  /// The blocks of the signing input before the table's region, which the start state stands
  /// for. They hold most of the header.
  pub skipped: usize,
  /// The last block of the signing input and of the disclosure, within their regions.
  pub signed_last: usize,
  pub attribute_last: usize,
  /// The offset of the payload's first character, counted from the first block in the table.
  pub payload_at: usize,
  /// Offsets in the decoded payload. The vct's is its key's, where its window starts. A missing
  /// nbf or exp has offset 0, and the rules read the payload's first bytes in its place.
  pub type_at: usize,
  pub digest_at: usize,
  pub not_before_at: usize,
  pub expiry_at: usize,
  pub device_key_at: usize,
  /// The start of the claim name's window in the decoded disclosure, which ends at the comma after
  /// the name, and whether a space follows that comma.
  pub claim_at: usize,
  pub spaced: bool,
  /// The full statement's `ssc` disclosure, or none for the age statement.
  pub nym: Option<SdJwtNym>,
}

/// What the prover knows of the full statement's `ssc` disclosure ([`crate::pseudonym`]).
#[derive(Clone, Debug)]
pub struct SdJwtNym {
  /// The disclosure's last block, within its region.
  pub last: usize,
  /// The offset of its listed digest in the decoded payload.
  pub digest_at: usize,
  /// The offset of `"ssc",` in the decoded disclosure, and whether a space follows the comma.
  pub claim_at: usize,
  pub spaced: bool,
}

/// The offset just after the comma that follows the claim name of a decoded disclosure
/// `["salt", "name", value]` (RFC 9901, clause 4.2.1): the name is the array's second string. A
/// salt holds no quote.
pub fn claim_end(claim: &[u8]) -> Result<usize, String> {
  let quote = |from: usize| {
    claim[from.min(claim.len())..]
      .iter()
      .position(|&b| b == b'"')
      .map(|at| from + at)
      .ok_or("a disclosure without a claim name")
  };
  let salt = quote(0)?;
  let name = quote(quote(salt + 1)? + 1)?;
  let close = quote(name + 1)?;
  if claim.get(close + 1) != Some(&b',') {
    return Err("a claim name without a comma after it".to_string());
  }
  Ok(close + 2)
}

impl SdJwtWitness {
  /// Finds each value, skips the blocks before the period, and places the rest of the signing
  /// input and the disclosure in the table. The rules read the period, so the table keeps it.
  /// The rules compare the vct and the claim name with the verifier's patterns, so the prover
  /// only finds the vct's key and the end of the claim name. The table's scan entries record the
  /// payload's phase and which time keys the payload lacks.
  pub fn new(
    signing_input: &[u8],
    disclosure: &[u8],
    issuer_key: PublicKey,
    issuer_signature: Signature,
  ) -> Result<Self, String> {
    Self::build(AGE, signing_input, disclosure, issuer_key, issuer_signature, None)
  }

  /// The witness of the full statement ([`crate::pseudonym`]), in the layout
  /// [`FULL_SD_JWT`]: the age statement's, the `ssc` disclosure `nym.ssc`, and the messages of
  /// the holder's secret seed and of the pseudonym in the table.
  pub fn full(
    signing_input: &[u8],
    disclosure: &[u8],
    nym: pseudonym::NymMessages,
    issuer_key: PublicKey,
    issuer_signature: Signature,
  ) -> Result<Self, String> {
    Self::build(FULL_SD_JWT, signing_input, disclosure, issuer_key, issuer_signature, Some(nym))
  }

  fn build(
    layout: Layout,
    signing_input: &[u8],
    disclosure: &[u8],
    issuer_key: PublicKey,
    issuer_signature: Signature,
    nym: Option<pseudonym::NymMessages>,
  ) -> Result<Self, String> {
    let period = find(signing_input, b".", "the period")?;
    let skipped = blocks_before(period);
    let payload =
      base64::decode(&signing_input[period + 1..]).ok_or("a payload not in base64url")?;
    let claim = base64::decode(disclosure).ok_or("a disclosure not in base64url")?;
    let listed = base64::encode(&sha256(disclosure));
    let claim_end = claim_end(&claim)?;
    let claim_at = claim_end
      .checked_sub(CLAIM_WINDOW.len)
      .ok_or("the claim name ends within 19 bytes of the disclosure's start")?;
    let payload_at = period + 1 - 64 * skipped;
    let [not_before_at, expiry_at] = TIMES.map(|time| find(&payload, time.key, "a time").ok());
    let scan =
      Scan { phase: payload_at % 4, absent: [not_before_at, expiry_at].map(|at| at.is_none()) };
    let mut messages = vec![(layout.attribute, disclosure.to_vec())];
    let nym = match (nym, layout.pseudonym) {
      (Some(nym), Some(regions)) => {
        messages.extend(nym.table_messages(&regions));
        let claim = base64::decode(nym.ssc).ok_or("an ssc disclosure not in base64url")?;
        let (claim_at, spaced) = pseudonym::claim_at(&claim)?;
        let listed = base64::encode(&sha256(nym.ssc));
        Some(SdJwtNym {
          last: last_block(nym.ssc.len()),
          digest_at: find(&payload, listed.as_bytes(), "the ssc disclosure's digest")?,
          claim_at,
          spaced,
        })
      }
      (None, None) => None,
      _ => return Err("the layout and the statement disagree".into()),
    };
    let messages: Vec<(Region, &[u8])> =
      messages.iter().map(|(region, bytes)| (*region, &bytes[..])).collect();
    Ok(SdJwtWitness {
      table: Arc::new(Table {
        scan: Some(scan),
        ..Table::with_messages(layout, signing_input, skipped, &messages)?
      }),
      issuer_key,
      issuer_signature,
      skipped,
      signed_last: last_block(signing_input.len()) - skipped,
      attribute_last: last_block(disclosure.len()),
      payload_at,
      type_at: find(&payload, TYPE_KEY, "vct")?,
      digest_at: find(&payload, listed.as_bytes(), "the disclosure's digest")?,
      not_before_at: not_before_at.unwrap_or(0),
      expiry_at: expiry_at.unwrap_or(0),
      device_key_at: find(&payload, DEVICE_KEY_X, "the device key")?,
      claim_at,
      spaced: claim.get(claim_end) == Some(&b' '),
      nym,
    })
  }
}

/// Reads the ten digits that follow `key` at offset `at` of the decoded payload, a time in
/// seconds since 1970. When the bit `absent` is one, the payload lacks the key, the rules do not
/// check the key, and the time is `none`.
fn optional_time<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  payload: &EncodedText,
  at: Option<usize>,
  key: &[u8],
  absent: &Lc,
  none: u64,
) -> Result<Lc, SynthesisError> {
  let text = payload.read(cs.namespace(|| "window"), at, key.len() + 10)?;
  let present = Lc::constant(t256::Scalar::ONE) - absent;
  expect_if(cs.namespace(|| "key"), &present, &text[..key.len()], key);
  let time = mul(cs.namespace(|| "time"), &present, &decimal(&text[key.len()..]))?;
  Ok(time + &absent.scale(t256::Scalar::from(none)))
}

/// Adds the scan to the step instance at the selected position. For each time key that the
/// payload lacks, the step's block holds none of the key's alignments at the payload's phase.
///
/// Every occurrence of a key in the payload puts the whole characters of one alignment
/// (see [`TIMES`]) at that alignment's phase, starting in one block of the signed message. The
/// step of that block finds them. They may run into the next block, so the step also reads the
/// first chunk of the next block, which is zero after the signed message's region.
///
/// Each character gets its own slot, so that a window is a short sum. At each of the 64
/// characters of the block, and for each key and alignment, the characters from there on,
/// packed as one integer, differ from the alignment's characters. The rule is on
/// when the payload lacks the key, the position lies in the signed message's region, and the
/// payload's phase gives the character the alignment's phase.
///
/// The whole characters leave some bits of the key's first and last byte open. They still fix
/// the key's name, its closing quote, and a byte from 0x30 to 0x3F after it. In JSON a quote after
/// a name closes a string, and of those bytes only a colon may follow a string. A payload that
/// lacks a key therefore passes the scan unless another of its keys ends in the same name. The
/// scan finds a key only when no space precedes its colon, the form in which the core reads every
/// key.
///
/// The scan also covers the end of the header, before the period in the first block, and the
/// padding after the payload. The padding holds no base64url text. The header is ASCII text,
/// and each alignment sets a bit that would be the top bit of an ASCII byte at every other
/// phase. The header therefore matches only where it holds the key itself, which RFC 7519
/// allows only as a copy of a payload claim.
pub fn scan<CS: ConstraintSystem<t256::Scalar>>(
  cs: CS,
  cells: &Cells,
  selector: &OneHot,
  block: &[Boolean],
) -> Result<(), SynthesisError> {
  scan_in(cs, cells, selector, block, &AGE, 0)
}

/// [`scan`] in `layout`, for the compression `k` of each step instance: its block sits at the
/// positions `per_instance · i + k`.
pub fn scan_in<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  cells: &Cells,
  selector: &OneHot,
  block: &[Boolean],
  layout: &Layout,
  k: usize,
) -> Result<(), SynthesisError> {
  let end = layout.signed.first + layout.signed.blocks;
  let position = |i: usize| layout.per_instance * i + k;
  let entries: Vec<Lc> = (0..layout.instances())
    .map(position)
    .map(|j| if j + 1 < end { cells.chunk(CHUNKS_PER_BLOCK * (j + 1)) } else { Lc::zero() })
    .collect();
  let next = selector.select(cs.namespace(|| "next chunk"), &entries)?;
  let next = bits(cs.namespace(|| "next chunk bits"), &next, 128)?;
  let text = bytes(&[block, &next[..]].concat())
    .iter()
    .enumerate()
    .map(|(i, byte)| {
      to_num(cs.namespace(|| format!("character slot {i}")), byte).map(|n| Lc::num(&n))
    })
    .collect::<Result<Vec<_>, _>>()?;

  let (phase, absent) = cells.scan();
  // The instances whose block lies in the signed region: a run from the first, since the region
  // starts at position 0.
  let instances =
    (0..layout.instances()).filter(|&i| (layout.signed.first..end).contains(&position(i)));
  let (low, high) = instances.fold((usize::MAX, 0), |(low, high), i| (low.min(i), high.max(i + 1)));
  let signed = selector.within(low..high);
  for ((name, time), absent) in ["nbf", "exp"].iter().zip(TIMES).zip(&absent) {
    let cs = &mut cs.namespace(|| *name);
    // gates[r] is one when the payload lacks the key, the position is in the signed region, and
    // the payload's phase is r.
    let on = mul(cs.namespace(|| "on"), absent, &signed)?;
    let gates = phase
      .iter()
      .enumerate()
      .map(|(r, bit)| mul(cs.namespace(|| format!("phase {r}")), &on, bit))
      .collect::<Result<Vec<_>, _>>()?;
    for k in 0..64 {
      for Alignment { phase: first, characters } in time.alignments {
        // With the payload at phase r, character k has phase (k − r) mod 4.
        let gate = &gates[(k + 4 - first) % 4];
        let packed = pack_bytes(&text[k..k + characters.len()]);
        let difference = packed - &Lc::constant(from_be(characters));
        nonzero_if(cs.namespace(|| format!("character {k} phase {first}")), gate, &difference)?;
      }
    }
  }
  Ok(())
}

/// The values of [`scan_in`] for the compression `k` of the step instance whose selector is set
/// at `index`, whose block the rules read as `block`, computed natively: the selection of the
/// next block's first chunk and its bits, the 80 characters' slots, and for nbf and exp the gate
/// products and each character's inverse slot, the inverse of its difference where its gate is
/// on and zero elsewhere.
pub fn scan_values(
  values: &mut Values,
  table: &Table,
  layout: &Layout,
  index: usize,
  block: &[u8; 64],
  k: usize,
) -> Result<(), SynthesisError> {
  let scan = table.scan.ok_or(SynthesisError::AssignmentMissing)?;
  let n = layout.instances();
  let end = layout.signed.first + layout.signed.blocks;
  let position = |i: usize| layout.per_instance * i + k;
  let next = select_values(values, n, index, |i| {
    let j = position(i);
    if j + 1 < end { table.chunk_value(CHUNKS_PER_BLOCK * (j + 1)) } else { t256::Scalar::ZERO }
  });
  let next = low_bytes(&next);
  values.byte_bits(&next);
  let text = [&block[..], &next[..]].concat();
  values.0.extend(text.iter().map(|&c| t256::Scalar::from(u64::from(c))));

  let instances = (0..n).filter(|&i| (layout.signed.first..end).contains(&position(i)));
  let (low, high) = instances.fold((usize::MAX, 0), |(low, high), i| (low.min(i), high.max(i + 1)));
  let signed = (low..high).contains(&index);
  for (time, absent) in TIMES.iter().zip(scan.absent) {
    let on = absent && signed;
    values.bit(on);
    for r in 0..4 {
      values.bit(on && scan.phase == r);
    }
    // Each character's slot is the inverse of its difference where its gate is on, and zero
    // elsewhere: the differences, then their inverses in one batch.
    let constants = time.alignments.map(|a| from_be(a.characters));
    let start = values.0.len();
    for c in 0..64 {
      for (Alignment { phase: first, characters }, constant) in
        time.alignments.iter().zip(&constants)
      {
        if on && scan.phase == (c + 4 - first) % 4 {
          let packed = text[c..c + characters.len()]
            .iter()
            .fold(0u64, |packed, &byte| 256 * packed + u64::from(byte));
          values.push(t256::Scalar::from(packed) - constant);
        } else {
          values.push(t256::Scalar::ZERO);
        }
      }
    }
    inverse_all(&mut values.0[start..]);
  }
  Ok(())
}

/// The age statement's rules that depend only on the credential, in `layout`: the issuer's
/// signature, the period and the payload's phase, the windows of the vct and the claim name, the
/// birth date, the validity and the device key. Returns the signed message as the rules read it,
/// the payload's start in it (as a sum of slots), and the facts.
fn age_part<'a, CS: ConstraintSystem<t256::Scalar>>(
  cs: &mut CS,
  cells: &'a Cells<'a>,
  w: Option<&SdJwtWitness>,
  layout: &Layout,
) -> Result<(Message<'a>, Lc, Facts), SynthesisError> {
  let (signed, signed_digest) = Message::open(
    cs.namespace(|| "signing input"),
    cells,
    layout.signed,
    w.map(|w| w.signed_last),
  )?;
  let (disclosure, disclosure_digest) = Message::open(
    cs.namespace(|| "disclosure"),
    cells,
    layout.attribute,
    w.map(|w| w.attribute_last),
  )?;

  // The issuer signed the signing input.
  let issuer_key = Point::alloc(cs.namespace(|| "issuer key"), w.map(|w| &w.issuer_key))?;
  let digest = digest_bits(cs.namespace(|| "signing input digest bits"), &signed_digest)?;
  let signature = w.map(|w| &w.issuer_signature);
  verify(cs.namespace(|| "issuer signature"), &digest, &issuer_key, signature)?;

  // The payload starts after the period. Base64url has no period, so the header and the
  // payload hold none, and the SHA-256 padding is too short to hold a read of the payload.
  let period = signed.read(cs.namespace(|| "period"), w.map(|w| w.payload_at - 1), 1)?;
  expect(cs.namespace(|| "period byte"), &period.bytes, b".");
  let payload = EncodedText {
    message: &signed,
    start: period.offset + &Lc::small(1),
    start_hint: w.map(|w| w.payload_at),
  };
  let claim_text = EncodedText { message: &disclosure, start: Lc::zero(), start_hint: Some(0) };

  // The scan entries. Exactly one phase bit is set, at the payload's first offset modulo 4,
  // and the flags are bits.
  let one = Lc::constant(t256::Scalar::ONE);
  let (phase, absent) = cells.scan();
  for (r, bit) in phase.iter().enumerate() {
    product(cs.namespace(|| format!("phase bit {r}")), bit, &(bit - &one), &Lc::zero());
  }
  let set = phase.iter().fold(Lc::zero(), |sum, bit| sum + bit);
  equal(cs.namespace(|| "one phase"), &set, &one);
  let groups =
    Lc::alloc(cs.namespace(|| "groups"), w.map(|w| t256::Scalar::from(w.payload_at as u64 / 4)))?;
  range_check(cs.namespace(|| "groups range"), &groups, OFFSET_BITS - 2)?;
  let residue =
    (0..4).fold(Lc::zero(), |sum, r| sum + &phase[r].scale(t256::Scalar::from(r as u64)));
  let start = groups.scale(t256::Scalar::from(4)) + &residue;
  equal(cs.namespace(|| "payload phase"), &payload.start, &start);
  for (name, flag) in ["nbf", "exp"].iter().zip(&absent) {
    product(cs.namespace(|| format!("{name} absent bit")), flag, &(flag - &one), &Lc::zero());
  }

  // The vct's window, which the rest segment compares with the verifier's pattern.
  let vct = payload.read_slots(cs.namespace(|| "vct"), w.map(|w| w.type_at), VCT_WINDOW.len)?;

  // The payload lists the disclosure's digest.
  let listed =
    payload.read(cs.namespace(|| "disclosure digest"), w.map(|w| w.digest_at), ENCODED_32)?;
  let listed = decode_chars(cs.namespace(|| "disclosure digest bits"), &listed)?;
  for h in 0..2 {
    let half = pack(&listed[128 * h..128 * (h + 1)]);
    equal(cs.namespace(|| format!("disclosure digest half {h}")), &half, &disclosure_digest[h]);
  }

  // The claim name's window, which the rest segment compares with the verifier's pattern, and
  // the birth date after it. After the comma comes a quote, or a space and a quote, and then the
  // ten characters of the date.
  let at = w.map(|w| w.claim_at);
  let mut claim =
    claim_text.read_slots(cs.namespace(|| "claim"), at, CLAIM_WINDOW.len + AFTER_CLAIM)?;
  let claim_lc: Vec<Lc> = claim.iter().map(Lc::num).collect();
  let spaced = alloc_bits(cs.namespace(|| "space"), w.map(|w| vec![w.spaced]), 1)?;
  let spaced = Lc::bit(&spaced[0]);
  let after_comma = after_comma(&spaced);
  equal(cs.namespace(|| "after the comma"), &claim_lc[CLAIM_WINDOW.len], &after_comma);
  let date = CLAIM_WINDOW.len + 1;
  let digits = DATE_DIGITS
    .iter()
    .map(|&i| {
      let (unspaced, spaced_digit) = (&claim_lc[date + i], &claim_lc[date + 1 + i]);
      mux(cs.namespace(|| format!("date digit {i}")), &spaced, unspaced, spaced_digit)
    })
    .collect::<Result<Vec<_>, _>>()?;
  let birth_date = decimal(&digits);

  // The validity the payload states. Without nbf it starts at 0, and without exp it has no end.
  let [nbf_absent, exp_absent] = &absent;
  let at = w.map(|w| w.not_before_at);
  let valid_from = optional_time(cs.namespace(|| "nbf"), &payload, at, NOT_BEFORE, nbf_absent, 0)?;
  let at = w.map(|w| w.expiry_at);
  let valid_until =
    optional_time(cs.namespace(|| "exp"), &payload, at, EXPIRY, exp_absent, NO_END)?;

  // The device key the payload binds, base64url-encoded again inside the JSON.
  let key_len = DEVICE_KEY_X.len() + ENCODED_32 + DEVICE_KEY_Y.len() + ENCODED_32;
  let key = payload.read(cs.namespace(|| "device key"), w.map(|w| w.device_key_at), key_len)?;
  let x_at = DEVICE_KEY_X.len();
  let y_at = x_at + ENCODED_32 + DEVICE_KEY_Y.len();
  expect(cs.namespace(|| "device key x key"), &key[..x_at], DEVICE_KEY_X);
  expect(cs.namespace(|| "device key y key"), &key[x_at + ENCODED_32..y_at], DEVICE_KEY_Y);
  let x = decode_chars(cs.namespace(|| "device key x bits"), &key[x_at..x_at + ENCODED_32])?;
  let y = decode_chars(cs.namespace(|| "device key y bits"), &key[y_at..y_at + ENCODED_32])?;
  let device_key = Point { x: pack(&x[..256]), y: pack(&y[..256]) };

  // The window's slots pass to the rest segment; the slots after it served the date.
  claim.truncate(CLAIM_WINDOW.len);
  let windows = [vct, claim];
  let facts = Facts { issuer_key, birth_date, valid_from, valid_until, device_key, windows };
  let payload_start = payload.start;
  Ok((signed, payload_start, facts))
}

/// A quote, or a space when `spaced` is one: the byte after the comma that follows a claim name.
fn after_comma(spaced: &Lc) -> Lc {
  let quote = t256::Scalar::from(u64::from(b'"'));
  Lc::constant(quote) + &spaced.scale(t256::Scalar::from(u64::from(b' ')) - quote)
}

/// The full statement's rules of the pseudonym that depend only on the credential
/// ([`crate::pseudonym`]): the `ssc` disclosure, its digest listed in the payload, its claim name
/// and its value, 64 hex digits that the rules decode into the commitment's 32 bytes, the secret
/// seed's message whose digest is those bytes, and the pseudonym's message of that seed. Returns
/// the slots the rest segment compares with the verifier's values.
fn nym_part<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  cells: &Cells,
  payload: &EncodedText,
  w: Option<&SdJwtWitness>,
  layout: &Layout,
) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
  let regions = layout.pseudonym.ok_or(SynthesisError::Unsatisfiable)?;
  let nym = match w {
    Some(w) => Some(w.nym.as_ref().ok_or(SynthesisError::AssignmentMissing)?),
    None => None,
  };
  let (disclosure, disclosure_digest) =
    Message::open(cs.namespace(|| "ssc disclosure"), cells, regions.ssc, nym.map(|n| n.last))?;

  // The payload lists the disclosure's digest.
  let at = nym.map(|n| n.digest_at);
  let listed = payload.read(cs.namespace(|| "ssc digest"), at, ENCODED_32)?;
  let listed = decode_chars(cs.namespace(|| "ssc digest bits"), &listed)?;
  for h in 0..2 {
    let half = pack(&listed[128 * h..128 * (h + 1)]);
    equal(cs.namespace(|| format!("ssc digest half {h}")), &half, &disclosure_digest[h]);
  }

  // The disclosure is `ssc`'s: `"ssc",`, a quote or a space and a quote, then the 64 hex digits
  // of the commitment's 32 bytes.
  let text = EncodedText { message: &disclosure, start: Lc::zero(), start_hint: Some(0) };
  let len = SD_JWT_CLAIM.len() + 2 + HEX_DIGITS;
  let claim = text.read(cs.namespace(|| "ssc claim"), nym.map(|n| n.claim_at), len)?;
  expect(cs.namespace(|| "ssc claim name"), &claim[..SD_JWT_CLAIM.len()], SD_JWT_CLAIM);
  let spaced = alloc_bits(cs.namespace(|| "ssc space"), nym.map(|n| vec![n.spaced]), 1)?;
  let spaced = Lc::bit(&spaced[0]);
  let after = SD_JWT_CLAIM.len();
  equal(cs.namespace(|| "ssc after the comma"), &claim[after], &after_comma(&spaced));
  let digits = (0..HEX_DIGITS)
    .map(|i| {
      let (unspaced, spaced_digit) = (&claim[after + 1 + i], &claim[after + 2 + i]);
      mux(cs.namespace(|| format!("ssc character {i}")), &spaced, unspaced, spaced_digit)
    })
    .collect::<Result<Vec<_>, _>>()?;
  let bytes = pseudonym::hex_bytes(cs.namespace(|| "ssc hex"), &digits)?;
  let ssc = [0, 1].map(|h| pack_bytes(&bytes[16 * h..16 * (h + 1)]));

  // The secret seed's digest is the disclosure's value, and the pseudonym's message is the seed's.
  pseudonym::commitment_and_slots(cs, cells, &regions, &ssc)
}

/// The core circuit for an SD-JWT VC.
#[derive(Clone, Debug)]
pub struct SdJwtCore {
  /// The credential, or none when setup only builds the shape.
  pub witness: Option<Arc<SdJwtWitness>>,
  /// The presentation, or none before the prover knows it.
  pub presentation: Option<Presentation>,
}

impl SdJwtCore {
  /// A core without values, for setup.
  pub fn blank() -> Self {
    SdJwtCore { witness: None, presentation: None }
  }
}

impl Core for SdJwtCore {
  const SCAN: bool = true;
}

impl VegaCircuit<T256HyraxEngine> for SdJwtCore {
  fn public_values(&self) -> Result<Vec<t256::Scalar>, SynthesisError> {
    let presentation = self.presentation.as_ref().ok_or(SynthesisError::AssignmentMissing)?;
    Ok(presentation.public.values(TimeEncoding::Seconds))
  }

  fn shared<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
  ) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
    table::allocate(cs.namespace(|| "table"), self.witness.as_ref().map(|w| &*w.table), true)
  }

  /// The rules that depend only on the credential.
  fn precommitted<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
    shared: &[AllocatedNum<t256::Scalar>],
  ) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
    let cells = Cells(shared);
    let (_, _, facts) = age_part(cs, &cells, self.witness.as_deref(), &AGE)?;
    facts.into_slots(cs.namespace(|| "facts"))
  }

  fn num_challenges(&self) -> usize {
    0
  }

  /// The rules of the presentation.
  fn synthesize<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
    _: &[AllocatedNum<t256::Scalar>],
    facts: &[AllocatedNum<t256::Scalar>],
    _: Option<&[t256::Scalar]>,
  ) -> Result<(), SynthesisError> {
    let presentation = self.presentation.as_ref();
    let times = TimeEncoding::Seconds;
    presentation::check(cs.namespace(|| "presentation"), facts, presentation, times, WINDOWS)
  }
}

/// The core circuit of the full statement for an SD-JWT VC: the age statement's rules in the
/// layout [`FULL_SD_JWT`], then the pseudonym's ([`crate::pseudonym`]).
#[derive(Clone, Debug)]
pub struct SdJwtNymCore {
  /// The credential with its `ssc` disclosure, or none when setup only builds the shape.
  pub witness: Option<Arc<SdJwtWitness>>,
  /// The presentation, or none before the prover knows it.
  pub presentation: Option<Presentation>,
  /// The verifier's verifier_input and the pseudonym, or none before the prover knows them.
  pub nym: Option<NymPublic>,
}

impl SdJwtNymCore {
  /// A core without values, for setup.
  pub fn blank() -> Self {
    SdJwtNymCore { witness: None, presentation: None, nym: None }
  }
}

impl Core for SdJwtNymCore {
  const SCAN: bool = true;
  const LAYOUT: Layout = FULL_SD_JWT;
}

impl VegaCircuit<T256HyraxEngine> for SdJwtNymCore {
  fn public_values(&self) -> Result<Vec<t256::Scalar>, SynthesisError> {
    let presentation = self.presentation.as_ref().ok_or(SynthesisError::AssignmentMissing)?;
    let nym = self.nym.as_ref().ok_or(SynthesisError::AssignmentMissing)?;
    let mut values = presentation.public.values(TimeEncoding::Seconds);
    values.extend(nym.values());
    Ok(values)
  }

  fn shared<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
  ) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
    table::allocate(cs.namespace(|| "table"), self.witness.as_ref().map(|w| &*w.table), true)
  }

  /// The rules that depend only on the credential: the age statement's, then the pseudonym's.
  fn precommitted<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
    shared: &[AllocatedNum<t256::Scalar>],
  ) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
    let w = self.witness.as_deref();
    let cells = Cells(shared);
    let (signed, start, facts) = age_part(cs, &cells, w, &FULL_SD_JWT)?;
    let mut slots = facts.into_slots(cs.namespace(|| "facts"))?;
    let payload = EncodedText { message: &signed, start, start_hint: w.map(|w| w.payload_at) };
    slots.extend(nym_part(cs.namespace(|| "pseudonym"), &cells, &payload, w, &FULL_SD_JWT)?);
    Ok(slots)
  }

  fn num_challenges(&self) -> usize {
    0
  }

  /// The rules of the presentation: the age statement's, then the pseudonym's.
  fn synthesize<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
    _: &[AllocatedNum<t256::Scalar>],
    facts: &[AllocatedNum<t256::Scalar>],
    _: Option<&[t256::Scalar]>,
  ) -> Result<(), SynthesisError> {
    let age = BASE_VALUES + WINDOWS[0].len + WINDOWS[1].len;
    if facts.len() != age + pseudonym::VALUES {
      return Err(SynthesisError::AssignmentMissing);
    }
    let (age_facts, nym_facts) = facts.split_at(age);
    let presentation = self.presentation.as_ref();
    let times = TimeEncoding::Seconds;
    presentation::check(cs.namespace(|| "presentation"), age_facts, presentation, times, WINDOWS)?;
    pseudonym::check(cs.namespace(|| "pseudonym check"), nym_facts, self.nym.as_ref())
  }
}
