//! The core circuit for an ISO/IEC 18013-5 mdoc.
//!
//! The issuer signs the mobile security object (MSO) with COSE_Sign1 (RFC 9052). The signed
//! message is the Sig_structure, which contains the MSO. The MSO lists the SHA-256 digest of the
//! IssuerSignedItemBytes of each attribute, and it holds the device key and the validity dates.
//! The shared table holds the Sig_structure and the IssuerSignedItemBytes of the birth date.
//!
//! The rules check what a dishonest prover could fake.
//!
//! | Rule | What the prover could otherwise do |
//! | --- | --- |
//! | The issuer signed the Sig_structure | Invent or alter a credential |
//! | The MSO's docType is the one the verifier names | Use another document of the same issuer, such as an mDL |
//! | The MSO lists the item's digest | Use an item the issuer never signed |
//! | The item's identifier is the one the verifier names | Pass another attribute off as the birth date |
//! | The device key, validFrom and validUntil come from the MSO | Pick them |
//! | Every read ends within the message's last block | Read bytes placed after the message |
//!
//! The rules do not parse CBOR. The trusted issuer writes each key name below once, at the place
//! the MSO or the item defines, so a window whose constant bytes match the key name sits there.
//! The docType and the identifier are the verifier's patterns, which start with their keys
//! ([`crate::request`]). The window of each ends where its text ends, and the rest segment
//! compares it with the pattern. A Sig_structure holds at least 48 bytes up to the docType's end,
//! because its header and the MSO's other entries come first, and an item holds at least 40 bytes
//! up to the identifier's end when its digestID and random come first, as ISO/IEC 18013-5 lists
//! them.
//! The attribute's digest is the exception, because every 32-byte string of the MSO starts with
//! the same two bytes. The device key's x- and y-coordinates are such strings. A holder could ask
//! for a device key whose coordinate is the digest of a forged item, but would then not know the
//! device key's private key, and the device signature stops the presentation.
//!
//! The device key is also the one part of the MSO whose bytes a holder could choose. A holder who
//! chose them freely could plant validFrom or validUntil and a date in them. The rules rely on the
//! wallet's hardware generating the key instead. A search for a key that plants validFrom takes
//! about 2^95 key generations.

use std::sync::Arc;

use bellpepper_core::{ConstraintSystem, SynthesisError, num::AllocatedNum};
use vega_prover::provider::{T256HyraxEngine, pt256::t256};
use vega_prover::traits::circuit::VegaCircuit;

use crate::app::Core;
use crate::gadgets::bits::{decimal, digest_bits, expect, pack_bytes};
use crate::gadgets::lc::{Lc, equal};
use crate::gadgets::p256::{Point, PublicKey, Signature, verify};
use crate::gadgets::window::{Message, find};
use crate::presentation::{
  self, BASE_VALUES, DATE_DIGITS, DATE_TIME_DIGITS, Facts, Presentation, TimeEncoding, window_slots,
};
use crate::pseudonym::{self, MDOC_IDENTIFIER, MDOC_VALUE, NymPublic, SSC_BYTES};
use crate::request::{DOC_TYPE_WINDOW, IDENTIFIER_WINDOW, Window};
use crate::table::{self, AGE, Cells, FULL_MDOC, Layout, Table, blocks_before, last_block, sha256};

pub use crate::request::{DOC_TYPE_KEY, IDENTIFIER_KEY};

/// The windows of an mdoc request: the docType and the element identifier.
pub const WINDOWS: [Window; 2] = [DOC_TYPE_WINDOW, IDENTIFIER_WINDOW];

/// A byte string of 32 bytes, as the MSO lists a digest.
pub const DIGEST: &[u8] = b"\x58\x20";

/// The key elementValue, the tag 1004 of a full-date, and the head of a 10-byte text.
pub const VALUE: &[u8] = b"\x6celementValue\xd9\x03\xec\x6a";

/// The key deviceKey and the start of its COSE_Key: kty EC2, crv P-256, and the head of x.
pub const DEVICE_KEY: &[u8] = b"\x69deviceKey\xa4\x01\x02\x20\x01\x21\x58\x20";

/// The label of y and the head of its 32-byte string, which follow x.
pub const DEVICE_KEY_Y: &[u8] = b"\x22\x58\x20";

/// The key validFrom, the tag 0 of a date-time, and the head of a 20-byte text.
pub const VALID_FROM: &[u8] = b"\x69validFrom\xc0\x74";

/// The key validUntil, the tag 0 of a date-time, and the head of a 20-byte text.
pub const VALID_UNTIL: &[u8] = b"\x6avalidUntil\xc0\x74";

/// What the prover knows about the credential: the table, the issuer's key and signature, and
/// where each value sits.
#[derive(Clone, Debug)]
pub struct MdocWitness {
  pub table: Arc<Table>,
  pub issuer_key: PublicKey,
  pub issuer_signature: Signature,
  /// The blocks of the Sig_structure before the table's region, which the start state stands for.
  pub skipped: usize,
  /// The last block of the Sig_structure and of the item, within their regions.
  pub signed_last: usize,
  pub attribute_last: usize,
  /// Offsets in the Sig_structure, counted from the first block in the table. The docType's is
  /// the start of its window, which ends where the docType's text ends.
  pub doc_type_at: usize,
  pub digest_at: usize,
  pub device_key_at: usize,
  pub valid_from_at: usize,
  pub valid_until_at: usize,
  /// Offsets in the item. The identifier's is the start of its window, which ends where the
  /// identifier's text ends.
  pub identifier_at: usize,
  pub value_at: usize,
  /// The full statement's `ssc` item, or none for the age statement.
  pub nym: Option<MdocNym>,
}

/// What the prover knows of the full statement's `ssc` item ([`crate::pseudonym`]).
#[derive(Clone, Debug)]
pub struct MdocNym {
  /// The item's last block, within its region.
  pub last: usize,
  /// The offset of the item's listed digest in the Sig_structure, counted from the first block
  /// in the table, and of its identifier's and value's windows in the item.
  pub digest_at: usize,
  pub identifier_at: usize,
  pub value_at: usize,
}

/// The start of the window of `len` bytes that ends where the CBOR text after `key` ends. Finds
/// the key's first occurrence in `bytes` and reads the text's head.
pub fn window_at(bytes: &[u8], key: &[u8], len: usize, what: &str) -> Result<usize, String> {
  let at = find(bytes, key, what)? + key.len();
  let head = *bytes.get(at).ok_or_else(|| format!("{what} has no value"))?;
  let (head_len, text_len) = match head {
    0x60..0x78 => (1, usize::from(head - 0x60)),
    0x78 => (2, usize::from(*bytes.get(at + 1).ok_or_else(|| format!("{what} is cut"))?)),
    _ => return Err(format!("{what} is not a text shorter than 256 bytes")),
  };
  let end = at + head_len + text_len;
  if end > bytes.len() {
    return Err(format!("{what} is cut"));
  }
  end.checked_sub(len).ok_or_else(|| format!("{what} ends within {len} bytes of the start"))
}

impl MdocWitness {
  /// Finds each value, skips the blocks before the first value the rules read, and places the
  /// rest of the Sig_structure and the item in the table. The rules compare the docType and the
  /// identifier with the verifier's patterns, so the prover only finds where their texts end.
  pub fn new(
    sig_structure: &[u8],
    item: &[u8],
    issuer_key: PublicKey,
    issuer_signature: Signature,
  ) -> Result<Self, String> {
    Self::build(AGE, sig_structure, item, issuer_key, issuer_signature, None)
  }

  /// The witness of the full statement ([`crate::pseudonym`]), in the layout
  /// [`FULL_MDOC`]: the age statement's, the `ssc` item `nym.ssc`, and the messages of the
  /// holder's secret seed and of the pseudonym in the table. The listed digest of the `ssc` item
  /// counts among the values whose first sets the skipped blocks.
  pub fn full(
    sig_structure: &[u8],
    item: &[u8],
    nym: pseudonym::NymMessages,
    issuer_key: PublicKey,
    issuer_signature: Signature,
  ) -> Result<Self, String> {
    Self::build(FULL_MDOC, sig_structure, item, issuer_key, issuer_signature, Some(nym))
  }

  fn build(
    layout: Layout,
    sig_structure: &[u8],
    item: &[u8],
    issuer_key: PublicKey,
    issuer_signature: Signature,
    nym: Option<pseudonym::NymMessages>,
  ) -> Result<Self, String> {
    let listed = [DIGEST, &sha256(item)].concat();
    let mut offsets = vec![
      window_at(sig_structure, DOC_TYPE_KEY, DOC_TYPE_WINDOW.len, "docType")?,
      find(sig_structure, &listed, "the item's digest")?,
      find(sig_structure, DEVICE_KEY, "deviceKey")?,
      find(sig_structure, VALID_FROM, "validFrom")?,
      find(sig_structure, VALID_UNTIL, "validUntil")?,
    ];
    if let Some(nym) = &nym {
      let listed = [DIGEST, &sha256(nym.ssc)].concat();
      offsets.push(find(sig_structure, &listed, "the ssc item's digest")?);
    }
    let skipped = blocks_before(*offsets.iter().min().expect("five offsets"));
    let offsets: Vec<usize> = offsets.iter().map(|at| at - 64 * skipped).collect();
    let mut messages = vec![(layout.attribute, item.to_vec())];
    let nym = match (nym, layout.pseudonym) {
      (Some(nym), Some(regions)) => {
        messages.extend(nym.table_messages(&regions));
        Some(MdocNym {
          last: last_block(nym.ssc.len()),
          digest_at: offsets[5],
          identifier_at: find(nym.ssc, MDOC_IDENTIFIER, "the ssc identifier")?,
          value_at: find(nym.ssc, MDOC_VALUE, "the ssc value")?,
        })
      }
      (None, None) => None,
      _ => return Err("the layout and the statement disagree".into()),
    };
    let messages: Vec<(table::Region, &[u8])> =
      messages.iter().map(|(region, bytes)| (*region, &bytes[..])).collect();
    Ok(MdocWitness {
      table: Arc::new(Table::with_messages(layout, sig_structure, skipped, &messages)?),
      issuer_key,
      issuer_signature,
      skipped,
      signed_last: last_block(sig_structure.len()) - skipped,
      attribute_last: last_block(item.len()),
      doc_type_at: offsets[0],
      digest_at: offsets[1],
      device_key_at: offsets[2],
      valid_from_at: offsets[3],
      valid_until_at: offsets[4],
      identifier_at: window_at(item, IDENTIFIER_KEY, IDENTIFIER_WINDOW.len, "the identifier")?,
      value_at: find(item, VALUE, "elementValue")?,
      nym,
    })
  }
}

/// Reads the date-time that follows `key` at offset `at`, as the number YYYYMMDDhhmmss.
fn date_time<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  message: &Message,
  at: Option<usize>,
  key: &[u8],
) -> Result<Lc, SynthesisError> {
  let window = message.read(cs.namespace(|| "window"), at, key.len() + 20)?;
  expect(cs.namespace(|| "key"), &window.bytes[..key.len()], key);
  let time = &window.bytes[key.len()..];
  Ok(decimal(&DATE_TIME_DIGITS.map(|i| time[i].clone())))
}

/// The age statement's rules that depend only on the credential, in `layout`: the issuer's
/// signature, the windows of the type and the attribute's name, the birth date, the device key
/// and the validity. Returns the signed message as the rules read it, and the facts.
fn age_part<'a, CS: ConstraintSystem<t256::Scalar>>(
  cs: &mut CS,
  cells: &'a Cells<'a>,
  w: Option<&MdocWitness>,
  layout: &Layout,
) -> Result<(Message<'a>, Facts), SynthesisError> {
  let (signed, signed_digest) = Message::open(
    cs.namespace(|| "Sig_structure"),
    cells,
    layout.signed,
    w.map(|w| w.signed_last),
  )?;
  let (item, item_digest) =
    Message::open(cs.namespace(|| "item"), cells, layout.attribute, w.map(|w| w.attribute_last))?;

  // The issuer signed the Sig_structure.
  let issuer_key = Point::alloc(cs.namespace(|| "issuer key"), w.map(|w| &w.issuer_key))?;
  let digest = digest_bits(cs.namespace(|| "Sig_structure digest bits"), &signed_digest)?;
  let signature = w.map(|w| &w.issuer_signature);
  verify(cs.namespace(|| "issuer signature"), &digest, &issuer_key, signature)?;

  // The docType's window, which the rest segment compares with the verifier's pattern.
  let at = w.map(|w| w.doc_type_at);
  let doc_type = signed.read(cs.namespace(|| "doc type"), at, DOC_TYPE_WINDOW.len)?;

  // The MSO lists the item's digest.
  let listed = signed.read(cs.namespace(|| "item digest"), w.map(|w| w.digest_at), 34)?;
  expect(cs.namespace(|| "item digest head"), &listed.bytes[..2], DIGEST);
  for (h, half_digest) in item_digest.iter().enumerate() {
    let half = pack_bytes(&listed.bytes[2 + 16 * h..18 + 16 * h]);
    equal(cs.namespace(|| format!("item digest half {h}")), &half, half_digest);
  }

  // The item's identifier, which the rest segment compares with the verifier's pattern, and
  // its value, a full-date.
  let at = w.map(|w| w.identifier_at);
  let identifier = item.read(cs.namespace(|| "element identifier"), at, IDENTIFIER_WINDOW.len)?;
  let value =
    item.read(cs.namespace(|| "element value"), w.map(|w| w.value_at), VALUE.len() + 10)?;
  expect(cs.namespace(|| "element value head"), &value.bytes[..VALUE.len()], VALUE);
  let date = &value.bytes[VALUE.len()..];
  let birth_date = decimal(&DATE_DIGITS.map(|i| date[i].clone()));

  // The device key the MSO binds.
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

  // The validity the MSO states.
  let at = w.map(|w| w.valid_from_at);
  let valid_from = date_time(cs.namespace(|| "valid from"), &signed, at, VALID_FROM)?;
  let at = w.map(|w| w.valid_until_at);
  let valid_until = date_time(cs.namespace(|| "valid until"), &signed, at, VALID_UNTIL)?;

  let windows = [
    window_slots(cs.namespace(|| "type"), &doc_type.bytes)?,
    window_slots(cs.namespace(|| "attribute"), &identifier.bytes)?,
  ];
  let facts = Facts { issuer_key, birth_date, valid_from, valid_until, device_key, windows };
  Ok((signed, facts))
}

/// The full statement's rules of the pseudonym that depend only on the credential
/// ([`crate::pseudonym`]): the `ssc` item, its digest listed in the Sig_structure, its identifier
/// and its value, a 32-byte string, the secret seed's message whose digest is that value, and the
/// pseudonym's message of that seed. Returns the slots the rest segment compares with the
/// verifier's values.
fn nym_part<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  cells: &Cells,
  signed: &Message,
  w: Option<&MdocWitness>,
  layout: &Layout,
) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
  let regions = layout.pseudonym.ok_or(SynthesisError::Unsatisfiable)?;
  let nym = match w {
    Some(w) => Some(w.nym.as_ref().ok_or(SynthesisError::AssignmentMissing)?),
    None => None,
  };
  let (item, item_digest) =
    Message::open(cs.namespace(|| "ssc item"), cells, regions.ssc, nym.map(|n| n.last))?;

  // The MSO lists the item's digest.
  let listed = signed.read(cs.namespace(|| "ssc digest"), nym.map(|n| n.digest_at), 34)?;
  expect(cs.namespace(|| "ssc digest head"), &listed.bytes[..2], DIGEST);
  for (h, half_digest) in item_digest.iter().enumerate() {
    let half = pack_bytes(&listed.bytes[2 + 16 * h..18 + 16 * h]);
    equal(cs.namespace(|| format!("ssc digest half {h}")), &half, half_digest);
  }

  // The item is `ssc`'s, and its value a 32-byte string.
  let at = nym.map(|n| n.identifier_at);
  let identifier = item.read(cs.namespace(|| "ssc identifier"), at, MDOC_IDENTIFIER.len())?;
  expect(cs.namespace(|| "ssc identifier bytes"), &identifier.bytes, MDOC_IDENTIFIER);
  let at = nym.map(|n| n.value_at);
  let value = item.read(cs.namespace(|| "ssc value"), at, MDOC_VALUE.len() + SSC_BYTES)?;
  let head = MDOC_VALUE.len();
  expect(cs.namespace(|| "ssc value head"), &value.bytes[..head], MDOC_VALUE);
  let ssc = [0, 1].map(|h| pack_bytes(&value.bytes[head + 16 * h..head + 16 * (h + 1)]));

  // The secret seed's digest is the item's value, and the pseudonym's message is the seed's.
  pseudonym::commitment_and_slots(cs, cells, &regions, &ssc)
}

/// The core circuit for an mdoc.
#[derive(Clone, Debug)]
pub struct MdocCore {
  /// The credential, or none when setup only builds the shape.
  pub witness: Option<Arc<MdocWitness>>,
  /// The presentation, or none before the prover knows it.
  pub presentation: Option<Presentation>,
}

impl MdocCore {
  /// A core without values, for setup.
  pub fn blank() -> Self {
    MdocCore { witness: None, presentation: None }
  }
}

impl Core for MdocCore {
  const SCAN: bool = false;
}

impl VegaCircuit<T256HyraxEngine> for MdocCore {
  fn public_values(&self) -> Result<Vec<t256::Scalar>, SynthesisError> {
    let presentation = self.presentation.as_ref().ok_or(SynthesisError::AssignmentMissing)?;
    Ok(presentation.public.values(TimeEncoding::Digits))
  }

  fn shared<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
  ) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
    table::allocate(cs.namespace(|| "table"), self.witness.as_ref().map(|w| &*w.table), false)
  }

  /// The rules that depend only on the credential.
  fn precommitted<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
    shared: &[AllocatedNum<t256::Scalar>],
  ) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
    let cells = Cells(shared);
    let (_, facts) = age_part(cs, &cells, self.witness.as_deref(), &AGE)?;
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
    let times = TimeEncoding::Digits;
    presentation::check(cs.namespace(|| "presentation"), facts, presentation, times, WINDOWS)
  }
}

/// The core circuit of the full statement for an mdoc: the age statement's rules in the layout
/// [`FULL_MDOC`], then the pseudonym's ([`crate::pseudonym`]).
#[derive(Clone, Debug)]
pub struct MdocNymCore {
  /// The credential with its `ssc` item, or none when setup only builds the shape.
  pub witness: Option<Arc<MdocWitness>>,
  /// The presentation, or none before the prover knows it.
  pub presentation: Option<Presentation>,
  /// The verifier's verifier_input and the pseudonym, or none before the prover knows them.
  pub nym: Option<NymPublic>,
}

impl MdocNymCore {
  /// A core without values, for setup.
  pub fn blank() -> Self {
    MdocNymCore { witness: None, presentation: None, nym: None }
  }
}

impl Core for MdocNymCore {
  const SCAN: bool = false;
  const LAYOUT: Layout = FULL_MDOC;
}

impl VegaCircuit<T256HyraxEngine> for MdocNymCore {
  fn public_values(&self) -> Result<Vec<t256::Scalar>, SynthesisError> {
    let presentation = self.presentation.as_ref().ok_or(SynthesisError::AssignmentMissing)?;
    let nym = self.nym.as_ref().ok_or(SynthesisError::AssignmentMissing)?;
    let mut values = presentation.public.values(TimeEncoding::Digits);
    values.extend(nym.values());
    Ok(values)
  }

  fn shared<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
  ) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
    table::allocate(cs.namespace(|| "table"), self.witness.as_ref().map(|w| &*w.table), false)
  }

  /// The rules that depend only on the credential: the age statement's, then the pseudonym's.
  fn precommitted<CS: ConstraintSystem<t256::Scalar>>(
    &self,
    cs: &mut CS,
    shared: &[AllocatedNum<t256::Scalar>],
  ) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
    let w = self.witness.as_deref();
    let cells = Cells(shared);
    let (signed, facts) = age_part(cs, &cells, w, &FULL_MDOC)?;
    let mut slots = facts.into_slots(cs.namespace(|| "facts"))?;
    slots.extend(nym_part(cs.namespace(|| "pseudonym"), &cells, &signed, w, &FULL_MDOC)?);
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
    let times = TimeEncoding::Digits;
    presentation::check(cs.namespace(|| "presentation"), age_facts, presentation, times, WINDOWS)?;
    pseudonym::check(cs.namespace(|| "pseudonym check"), nym_facts, self.nym.as_ref())
  }
}
