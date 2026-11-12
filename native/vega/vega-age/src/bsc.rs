//! The nym_auth statement on the rulebook v0.5 attestation: the mdoc `eu.europa.ec.eudi.nym_auth.1`
//! in its compact profile, with the items `bsc` (digestID 0) and `psc` (digestID 1), each a
//! 32-byte commitment. `bsc` = SHA-256(secret_seed ‖ birth_date): the holder's 16-byte
//! secret_seed and the 10-byte full-date YYYY-MM-DD, both kept outside the credential. `psc` is
//! signed and not read.
//!
//! One proof shows, nothing disclosed but the pseudonym:
//!
//! | Rule | What the prover could otherwise do |
//! | --- | --- |
//! | The issuer signed the Sig_structure, hashed whole from the initial value (the start state is the initial value) | Invent or alter a credential |
//! | The Sig_structure's and the `bsc` item's SHA-256 padding hold at their private lengths L ([`crate::gadgets::padding`]), and every read ends within L | Read bytes placed after the message, in its padding |
//! | The MSO's docType is the verifier's | Use another document of the same issuer |
//! | The device key, validFrom and validUntil come from the MSO | Pick them |
//! | validFrom ≤ proof_time ≤ validUntil, both bounds included (the rulebook) | Use an expired credential |
//! | The MSO lists the `bsc` item's digest; the item's identifier is `bsc` and its value a 32-byte string | Use an item the issuer never signed, or another attribute |
//! | The opening's message is secret_seed ‖ birth_date, padded, and its digest is `bsc` | Use a seed or a birth date that does not open `bsc` |
//! | E ≤ birth_date ≤ C, on the opening's digits | Pass the age check with another birth date |
//! | The pseudonym's message is DST, that seed, 32 zero bytes and the verifier's verifier_input, and the pseudonym its digest | Present another verifier's pseudonym, or one of another seed |
//! | The device key signed the verifier's challenge | Replay a presentation |
//!
//! The table ([`BSC_MDOC`], 16 positions): the Sig_structure 0 to 6 (7 blocks, the compact
//! profile's 376 to 439 bytes), the `bsc` item 7 and 8 (2 blocks, 56 to 119 bytes), the opening 9
//! (26 bytes), the pseudonym's message 10 and 11; 12 to 15 hold no message. Every message chains
//! from the initial value: the core holds the start state to it. Every holder of the profile gets
//! the same circuits, so the circuits reveal nothing of the credential's lengths.
//!
//! The digits of the birth date are the issuer's (it computed `bsc` from them), and are not range
//! checked, as the PID's are not.
//!
//! **Public values** (15): the issuer key's x and y; E and C as YYYYMMDD (0 and 99999999 for a
//! missing bound); proof_time as YYYYMMDDhhmmss; the challenge digest's halves; the docType
//! pattern (2 limbs and the thermometer, [`crate::request`]); verifier_input's three values; the
//! pseudonym's halves, which the proof reports ([`crate::app::accept_pseudonym`]).

use std::sync::Arc;

use bellpepper_core::{ConstraintSystem, SynthesisError, num::AllocatedNum};
use vega_prover::provider::{T256HyraxEngine, pt256::t256};
use vega_prover::traits::circuit::VegaCircuit;

use crate::app::Core;
use crate::gadgets::bits::{
  alloc_bits, bytes, decimal, digest_bits, expect, pack, pack_bytes, range_check,
};
use crate::gadgets::lc::{Lc, equal, from_be, to_be, to_num};
use crate::gadgets::p256::{Point, PublicKey, Signature, verify};
use crate::gadgets::padding;
use crate::gadgets::window::{Message, find};
use crate::mdoc::{
  DEVICE_KEY, DEVICE_KEY_Y, DIGEST, VALID_FROM, VALID_UNTIL, date_time, window_at,
};
use crate::presentation::{DATE_DIGITS, Date, Time, window_slots};
use crate::pseudonym::{self, MDOC_VALUE, NymPublic, SSC_BYTES, constant};
use crate::request::{self, DOC_TYPE_KEY, DOC_TYPE_WINDOW, Pattern};
use crate::table::{
  CHUNKS_PER_BLOCK, Cells, Layout, PseudonymRegions, Region, Table, iv_bytes, sha256, state_half,
};

/// The rulebook's docType and namespace.
pub const DOC_TYPE: &str = "eu.europa.ec.eudi.nym_auth.1";

/// The `bsc` item's key elementIdentifier and the 3-byte text `bsc`.
pub const BSC_IDENTIFIER: &[u8] = b"\x71elementIdentifier\x63bsc";

/// The opening's bytes: secret_seed's 16, birth_date's 10.
pub const OPENING_BYTES: usize = 26;

/// The Sig_structure's and the item's regions, of exactly their padded blocks.
pub const SIGNED: Region = Region { first: 0, blocks: 7 };
pub const ITEM: Region = Region { first: 7, blocks: 2 };
pub const OPENING: Region = Region { first: 9, blocks: 1 };
pub const NYM: Region = Region { first: 10, blocks: 2 };

/// The table of the rulebook v0.5 statement: 16 positions, one compression per step instance.
/// The pseudonym's regions name the item as `ssc` (it is the commitment's item) and the opening
/// as the seed's message, so that every region but the signed one starts from the initial value.
pub const BSC_MDOC: Layout = Layout {
  signed: SIGNED,
  attribute: ITEM,
  pseudonym: Some(PseudonymRegions { ssc: ITEM, seed: OPENING, nym: NYM }),
  per_instance: 1,
  budget: 1 << 15,
  positions: 16,
};

/// The public values before verifier_input's.
pub const BASE_VALUES: usize = 7;
/// The public values the verifier names: the base, the docType pattern's, verifier_input's.
pub const NAMED_VALUES: usize = BASE_VALUES + 3 + 3;

/// C when the request sets no minimum age: every date is on or before it.
pub const NO_CUTOFF: u64 = 99_999_999;

/// The opening's message: secret_seed ‖ birth_date.
pub fn opening(secret_seed: &[u8; 16], birth_date: &[u8; 10]) -> [u8; OPENING_BYTES] {
  let mut o = [0u8; OPENING_BYTES];
  o[..16].copy_from_slice(secret_seed);
  o[16..].copy_from_slice(birth_date);
  o
}

/// What the prover knows about the credential: the table and where each value sits.
#[derive(Clone, Debug)]
pub struct BscWitness {
  pub table: Arc<Table>,
  pub issuer_key: PublicKey,
  pub issuer_signature: Signature,
  /// The Sig_structure's and the item's lengths.
  pub signed_len: usize,
  pub item_len: usize,
  /// Offsets in the Sig_structure; the docType's is the start of its window, which ends where
  /// the docType's text ends.
  pub doc_type_at: usize,
  pub digest_at: usize,
  pub device_key_at: usize,
  pub valid_from_at: usize,
  pub valid_until_at: usize,
  /// Offsets in the item.
  pub identifier_at: usize,
  pub value_at: usize,
}

impl BscWitness {
  /// Finds each value and places the messages in the table: the Sig_structure, the `bsc` item
  /// (its IssuerSignedItemBytes, tag 24 included, as the MSO digests it), the opening and the
  /// pseudonym's message for `verifier_input`. Refuses a credential outside the compact profile's
  /// sizes.
  pub fn new(
    sig_structure: &[u8],
    item: &[u8],
    secret_seed: &[u8; 16],
    birth_date: &[u8; 10],
    verifier_input: &[u8; 32],
    issuer_key: PublicKey,
    issuer_signature: Signature,
  ) -> Result<Self, String> {
    if !padding::lengths(SIGNED.blocks).contains(&sig_structure.len()) {
      return Err(format!(
        "the Sig_structure has {} bytes, not 376 to 439 (7 SHA-256 blocks)",
        sig_structure.len()
      ));
    }
    if !padding::lengths(ITEM.blocks).contains(&item.len()) {
      return Err(format!(
        "the bsc item has {} bytes, not 56 to 119 (2 SHA-256 blocks)",
        item.len()
      ));
    }
    let listed = [DIGEST, &sha256(item)].concat();
    let opening = opening(secret_seed, birth_date);
    let messages: [(Region, Vec<u8>); 3] = [
      (ITEM, item.to_vec()),
      (OPENING, opening.to_vec()),
      (NYM, pseudonym::message(secret_seed, verifier_input)),
    ];
    let messages: Vec<(Region, &[u8])> = messages.iter().map(|(r, m)| (*r, &m[..])).collect();
    Ok(BscWitness {
      table: Arc::new(Table::with_messages(BSC_MDOC, sig_structure, 0, &messages)?),
      issuer_key,
      issuer_signature,
      signed_len: sig_structure.len(),
      item_len: item.len(),
      doc_type_at: window_at(sig_structure, DOC_TYPE_KEY, DOC_TYPE_WINDOW.len, "docType")?,
      digest_at: find(sig_structure, &listed, "the bsc item's digest")?,
      device_key_at: find(sig_structure, DEVICE_KEY, "deviceKey")?,
      valid_from_at: find(sig_structure, VALID_FROM, "validFrom")?,
      valid_until_at: find(sig_structure, VALID_UNTIL, "validUntil")?,
      identifier_at: find(item, BSC_IDENTIFIER, "the bsc identifier")?,
      value_at: find(item, MDOC_VALUE, "the bsc value")?,
    })
  }
}

/// The values the verifier names, and the pseudonym.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BscPublic {
  pub issuer_key: PublicKey,
  /// E: the earliest birth date that passes, none for no maximum age.
  pub born_from: Option<Date>,
  /// C: the latest birth date that passes, none for no minimum age.
  pub born_by: Option<Date>,
  /// proof_time.
  pub now: Time,
  /// The digest of the message the device key signs ([`crate::challenge`]).
  pub challenge: [u8; 32],
  /// The docType's pattern ([`Pattern::doc_type`]).
  pub doc_type: Pattern,
  pub verifier_input: [u8; 32],
  /// The pseudonym, which the proof reports.
  pub pseudonym: [u8; 32],
}

impl BscPublic {
  /// The values the verifier names, in their order ([`crate::app::accept_pseudonym`]'s
  /// `expected`).
  pub fn named_values(&self) -> Vec<t256::Scalar> {
    let mut values = vec![
      from_be(&self.issuer_key.x),
      from_be(&self.issuer_key.y),
      t256::Scalar::from(self.born_from.map_or(0, |d| d.digits())),
      t256::Scalar::from(self.born_by.map_or(NO_CUTOFF, |d| d.digits())),
      t256::Scalar::from(self.now.digits()),
      from_be(&self.challenge[..16]),
      from_be(&self.challenge[16..]),
    ];
    values.extend(self.doc_type.values());
    values.extend(NymPublic::verifier_values(&self.verifier_input));
    values
  }

  /// Every public value of the core: the named ones, then the pseudonym's halves.
  pub fn values(&self) -> Vec<t256::Scalar> {
    let mut values = self.named_values();
    values.extend([from_be(&self.pseudonym[..16]), from_be(&self.pseudonym[16..])]);
    values
  }
}

/// What the prover adds for one presentation: the values, and the device key's signature on the
/// challenge.
#[derive(Clone, Debug)]
pub struct BscPresentation {
  pub public: BscPublic,
  pub device_signature: Signature,
}

/// The opening's rules and the pseudonym's (module documentation): the opening's chunks are the
/// seed, then the birth date's 10 bytes with the padding's 0x80, zeros, and the length 208; the
/// pseudonym's first block holds DST, the seed and prover_input's first bytes. Returns the
/// opening's digest (two halves), the birth date as YYYYMMDD, and the five values the rest
/// segment compares with verifier_input and the pseudonym.
fn opening_and_nym<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  cells: &Cells,
) -> Result<([Lc; 2], Lc, [Lc; pseudonym::VALUES]), SynthesisError> {
  let chunk = |j: usize, c: usize| cells.chunk(CHUNKS_PER_BLOCK * j + c);
  let o = OPENING.first;
  let seed = chunk(o, 0);

  // Chunk 1: the birth date's 10 bytes, then 0x80 and five zero bytes. Its 128-bit range (the
  // steps') and the birth date's 80 bits make the split exact.
  let marker = t256::Scalar::from(0x80u64) * t256::Scalar::from(1u64 << 40);
  let date_value = chunk(o, 1).value.map(|v| {
    let be = to_be(&v);
    be[16..26].iter().flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1)).collect::<Vec<_>>()
  });
  let date_bits = alloc_bits(cs.namespace(|| "birth date bits"), date_value, 80)?;
  let date = pack(&date_bits);
  let shifted = date.scale(t256::Scalar::from(1u64 << 48)) + &Lc::constant(marker);
  equal(cs.namespace(|| "opening chunk 1"), &chunk(o, 1), &shifted);
  let digits = bytes(&date_bits);
  let birth_date = decimal(&DATE_DIGITS.map(|i| digits[i].clone()));

  // Chunks 2 and 3: zeros, then the length 26 · 8 = 208 as the last bytes.
  equal(cs.namespace(|| "opening chunk 2"), &chunk(o, 2), &Lc::zero());
  let mut last = [0u8; 16];
  last[14..].copy_from_slice(&((8 * OPENING_BYTES) as u16).to_be_bytes());
  equal(cs.namespace(|| "opening chunk 3"), &chunk(o, 3), &constant(&last));
  let digest = [cells.state(o, 0), cells.state(o, 1)];

  // The pseudonym's two blocks, from the opening's seed (the v0.4 core's rules).
  let facts = pseudonym::nym_blocks(&mut cs, cells, NYM.first, &seed)?;
  Ok((digest, birth_date, facts))
}

/// The core circuit of the rulebook v0.5 statement.
#[derive(Clone, Debug)]
pub struct BscCore {
  /// The credential, or none when setup only builds the shape.
  pub witness: Option<Arc<BscWitness>>,
  /// The presentation, or none before the prover knows it.
  pub presentation: Option<BscPresentation>,
}

impl BscCore {
  /// A core without values, for setup.
  pub fn blank() -> Self {
    BscCore { witness: None, presentation: None }
  }
}

impl Core for BscCore {
  const SCAN: bool = false;
  const LAYOUT: Layout = BSC_MDOC;
}

/// The facts the precommitted segment passes to the rest: the issuer key's x and y, the birth
/// date, validFrom, validUntil, the device key's x and y, the docType window's 48 bytes, and the
/// pseudonym's five values.
const FACTS: usize = 7 + 48 + pseudonym::VALUES;

impl VegaCircuit<T256HyraxEngine> for BscCore {
  fn public_values(&self) -> Result<Vec<t256::Scalar>, SynthesisError> {
    let presentation = self.presentation.as_ref().ok_or(SynthesisError::AssignmentMissing)?;
    Ok(presentation.public.values())
  }

  fn shared<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
  ) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
    let table = self.witness.as_ref().map(|w| &*w.table);
    crate::table::allocate_positions(cs.namespace(|| "table"), BSC_MDOC.positions, table, false)
  }

  /// The rules that depend only on the credential.
  fn precommitted<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
    shared: &[AllocatedNum<t256::Scalar>],
  ) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
    let w = self.witness.as_deref();
    let cells = Cells::of(shared, &BSC_MDOC);

    // The Sig_structure is hashed whole: its chain starts from the initial value.
    for h in 0..2 {
      let start = cells.state_before_in(&BSC_MDOC, SIGNED.first, h);
      equal(
        cs.namespace(|| format!("start state half {h}")),
        &start,
        &Lc::constant(state_half(&iv_bytes(), h)),
      );
    }

    // The Sig_structure: its padding at its length, its digest, the issuer's signature.
    let signed_len = padding::padded(
      cs.namespace(|| "Sig_structure padding"),
      &cells,
      SIGNED,
      w.map(|w| w.signed_len),
    )?;
    let (signed, signed_digest) = Message::of_length(&cells, SIGNED, signed_len);
    let issuer_key = Point::alloc(cs.namespace(|| "issuer key"), w.map(|w| &w.issuer_key))?;
    let digest = digest_bits(cs.namespace(|| "Sig_structure digest bits"), &signed_digest)?;
    verify(
      cs.namespace(|| "issuer signature"),
      &digest,
      &issuer_key,
      w.map(|w| &w.issuer_signature),
    )?;

    // The docType's window, which the rest segment compares with the verifier's pattern.
    let doc_type =
      signed.read(cs.namespace(|| "doc type"), w.map(|w| w.doc_type_at), DOC_TYPE_WINDOW.len)?;

    // The device key the MSO binds, and the validity it states.
    let key_len = DEVICE_KEY.len() + 32 + DEVICE_KEY_Y.len() + 32;
    let key = signed.read(cs.namespace(|| "device key"), w.map(|w| w.device_key_at), key_len)?;
    let x_at = DEVICE_KEY.len();
    let y_at = x_at + 32 + DEVICE_KEY_Y.len();
    expect(cs.namespace(|| "device key head"), &key.bytes[..x_at], DEVICE_KEY);
    expect(cs.namespace(|| "device key y head"), &key.bytes[x_at + 32..y_at], DEVICE_KEY_Y);
    let device_key = Point {
      x: pack_bytes(&key.bytes[x_at..x_at + 32]),
      y: pack_bytes(&key.bytes[y_at..y_at + 32]),
    };
    let valid_from =
      date_time(cs.namespace(|| "valid from"), &signed, w.map(|w| w.valid_from_at), VALID_FROM)?;
    let valid_until =
      date_time(cs.namespace(|| "valid until"), &signed, w.map(|w| w.valid_until_at), VALID_UNTIL)?;

    // The bsc item: its padding, its digest listed in the MSO, its identifier and its value.
    let item_len =
      padding::padded(cs.namespace(|| "bsc item padding"), &cells, ITEM, w.map(|w| w.item_len))?;
    let (item, item_digest) = Message::of_length(&cells, ITEM, item_len);
    let listed = signed.read(cs.namespace(|| "bsc digest"), w.map(|w| w.digest_at), 34)?;
    expect(cs.namespace(|| "bsc digest head"), &listed.bytes[..2], DIGEST);
    for (h, half) in item_digest.iter().enumerate() {
      equal(
        cs.namespace(|| format!("bsc digest half {h}")),
        &pack_bytes(&listed.bytes[2 + 16 * h..18 + 16 * h]),
        half,
      );
    }
    let identifier = item.read(
      cs.namespace(|| "bsc identifier"),
      w.map(|w| w.identifier_at),
      BSC_IDENTIFIER.len(),
    )?;
    expect(cs.namespace(|| "bsc identifier bytes"), &identifier.bytes, BSC_IDENTIFIER);
    let value = item.read(
      cs.namespace(|| "bsc value"),
      w.map(|w| w.value_at),
      MDOC_VALUE.len() + SSC_BYTES,
    )?;
    let head = MDOC_VALUE.len();
    expect(cs.namespace(|| "bsc value head"), &value.bytes[..head], MDOC_VALUE);
    let bsc = [0, 1].map(|h| pack_bytes(&value.bytes[head + 16 * h..head + 16 * (h + 1)]));

    // The opening opens bsc; the birth date; the pseudonym's message.
    let (opening_digest, birth_date, nym) = opening_and_nym(cs.namespace(|| "opening"), &cells)?;
    for (h, (o, b)) in opening_digest.iter().zip(&bsc).enumerate() {
      equal(cs.namespace(|| format!("opening digest half {h} is bsc")), o, b);
    }

    let facts = [
      ("issuer key x", issuer_key.x),
      ("issuer key y", issuer_key.y),
      ("birth date", birth_date),
      ("valid from", valid_from),
      ("valid until", valid_until),
      ("device key x", device_key.x),
      ("device key y", device_key.y),
    ];
    let mut slots = facts
      .iter()
      .map(|(name, fact)| to_num(cs.namespace(|| *name), fact))
      .collect::<Result<Vec<_>, _>>()?;
    slots.extend(window_slots(cs.namespace(|| "doc type window"), &doc_type.bytes)?);
    slots.extend(pseudonym::into_slots(cs.namespace(|| "pseudonym"), &nym)?);
    Ok(slots)
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
    if presentation.is_some_and(|p| p.public.doc_type.window() != DOC_TYPE_WINDOW) {
      return Err(SynthesisError::Unsatisfiable);
    }
    let values = presentation.map(|p| p.public.values());
    let names = [
      "issuer key x",
      "issuer key y",
      "born from",
      "born by",
      "now",
      "challenge high",
      "challenge low",
    ];
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
    // A rest segment given other slots, such as a state prepared from replays, has no witness.
    if facts.len() != FACTS {
      return Err(SynthesisError::AssignmentMissing);
    }
    let fact: Vec<Lc> = facts[..7].iter().map(Lc::num).collect();
    let [issuer_x, issuer_y, birth_date, valid_from, valid_until, device_x, device_y] = &fact[..]
    else {
      unreachable!("seven facts");
    };
    let [public_x, public_y, born_from, born_by, now, challenge_high, challenge_low] = &public[..]
    else {
      unreachable!("seven public values");
    };

    // The docType is the verifier's.
    let type_values =
      values.as_ref().map(|v| &v[BASE_VALUES..BASE_VALUES + DOC_TYPE_WINDOW.public_count()]);
    request::check(cs.namespace(|| "type"), DOC_TYPE_WINDOW, &facts[7..7 + 48], type_values)?;

    // The issuer key is the verifier's.
    equal(cs.namespace(|| "same issuer key x"), issuer_x, public_x);
    equal(cs.namespace(|| "same issuer key y"), issuer_y, public_y);

    // E ≤ birth_date ≤ C (dates below 10^8 < 2^27).
    range_check(cs.namespace(|| "born from the earliest date"), &(birth_date - born_from), 27)?;
    range_check(cs.namespace(|| "born by the cutoff"), &(born_by - birth_date), 27)?;

    // validFrom ≤ proof_time ≤ validUntil, both bounds included (times below 10^14 < 2^47).
    range_check(cs.namespace(|| "validity started"), &(now - valid_from), 47)?;
    range_check(cs.namespace(|| "not expired"), &(valid_until - now), 47)?;

    // The device key signed the challenge.
    let halves = [challenge_high.clone(), challenge_low.clone()];
    let challenge = digest_bits(cs.namespace(|| "challenge bits"), &halves)?;
    let device_key = Point { x: device_x.clone(), y: device_y.clone() };
    verify(
      cs.namespace(|| "device signature"),
      &challenge,
      &device_key,
      presentation.map(|p| &p.device_signature),
    )?;

    // verifier_input and the pseudonym.
    let nym = presentation.map(|p| NymPublic {
      verifier_input: p.public.verifier_input,
      pseudonym: p.public.pseudonym,
    });
    pseudonym::check(cs.namespace(|| "pseudonym"), &facts[7 + 48..], nym.as_ref())
  }
}
