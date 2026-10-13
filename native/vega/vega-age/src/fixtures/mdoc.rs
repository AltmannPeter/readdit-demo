//! A test PID as an ISO/IEC 18013-5 mdoc.

use super::cbor::{Value, int, record, tag, text};
use super::{EcdsaSignature, ISSUED, KeyPair, point_with_x, salt};
use crate::gadgets::p256::PublicKey;
use crate::presentation::{Date, Time};
use crate::table::sha256;

/// The document type and the namespace of the PID.
pub const PID: &str = "eu.europa.ec.eudi.pid.1";

/// The document type of an mDL, which is not a PID.
pub const MDL: &str = "org.iso.18013.5.1.mDL";

/// An issued mdoc: the Sig_structure the issuer signed, the signature, and the
/// IssuerSignedItemBytes of each attribute.
#[derive(Clone, Debug)]
pub struct Mdoc {
  pub sig_structure: Vec<u8>,
  pub signature: EcdsaSignature,
  pub items: Vec<(String, Vec<u8>)>,
}

impl Mdoc {
  /// The IssuerSignedItemBytes of an attribute.
  pub fn item(&self, identifier: &str) -> &[u8] {
    let (_, bytes) = self.items.iter().find(|(name, _)| name == identifier).expect("an attribute");
    bytes
  }
}

/// A full-date, as ISO/IEC 18013-5 writes one: tag 1004 on the text YYYY-MM-DD.
pub fn full_date(date: &Date) -> Value {
  tag(1004, text(&date.text()))
}

/// The attributes of the test PID.
pub fn attributes(birth_date: &Date) -> Vec<(&'static str, Value)> {
  vec![
    ("family_name", text("Mustermann")),
    ("given_name", text("Erika")),
    ("birth_date", full_date(birth_date)),
    ("birth_place", text("Berlin")),
    ("nationality", Value::Array(vec![text("DE")])),
    ("age_over_18", Value::Bool(true)),
    ("issuing_authority", text("Test PID Issuer")),
    ("issuing_country", text("DE")),
    ("expiry_date", full_date(&Date { year: 2031, month: 1, day: 1 })),
  ]
}

/// IssuerSignedItemBytes: tag 24 on the encoded IssuerSignedItem.
pub fn item_bytes(digest_id: u64, random: &[u8], identifier: &str, value: Value) -> Vec<u8> {
  let item = record(vec![
    ("digestID", Value::Unsigned(digest_id)),
    ("random", Value::Bytes(random.to_vec())),
    ("elementIdentifier", text(identifier)),
    ("elementValue", value),
  ]);
  tag(24, Value::Bytes(item.encode())).encode()
}

/// The items of the test PID, each with its own random salt.
pub fn items(birth_date: &Date) -> Vec<(String, Vec<u8>)> {
  attributes(birth_date)
    .into_iter()
    .enumerate()
    .map(|(i, (name, value))| {
      let random = salt(&format!("mdoc random {name}"));
      (name.to_string(), item_bytes(i as u64, &random, name, value))
    })
    .collect()
}

/// Issues an mdoc of type `doc_type`, with its items in the namespace of the same name. The MSO
/// lists each item's digest, binds the device key, is valid from its issuance, and expires at
/// `valid_until`. The Sig_structure is the one COSE_Sign1 signs (RFC 9052, clause 4.4).
pub fn issue(
  issuer: &KeyPair,
  device_key: &PublicKey,
  valid_until: &Time,
  doc_type: &str,
  items: Vec<(String, Vec<u8>)>,
) -> Mdoc {
  let digests = items
    .iter()
    .enumerate()
    .map(|(i, (_, bytes))| (Value::Unsigned(i as u64), Value::Bytes(sha256(bytes).to_vec())))
    .collect();
  let cose_key = Value::Map(vec![
    (int(1), int(2)),
    (int(-1), int(1)),
    (int(-2), Value::Bytes(device_key.x.to_vec())),
    (int(-3), Value::Bytes(device_key.y.to_vec())),
  ]);
  let mso = record(vec![
    ("version", text("1.0")),
    ("digestAlgorithm", text("SHA-256")),
    ("valueDigests", Value::Map(vec![(text(doc_type), Value::Map(digests))])),
    ("deviceKeyInfo", record(vec![("deviceKey", cose_key)])),
    ("docType", text(doc_type)),
    (
      "validityInfo",
      record(vec![
        ("signed", tag(0, text(&ISSUED.text()))),
        ("validFrom", tag(0, text(&ISSUED.text()))),
        ("validUntil", tag(0, text(&valid_until.text()))),
      ]),
    ),
  ]);
  let payload = tag(24, Value::Bytes(mso.encode())).encode();
  let protected = Value::Map(vec![(int(1), int(-7))]).encode();
  let sig_structure = Value::Array(vec![
    text("Signature1"),
    Value::Bytes(protected),
    Value::Bytes(Vec::new()),
    Value::Bytes(payload),
  ])
  .encode();
  let signature = issuer.sign(&sig_structure);
  Mdoc { sig_structure, signature, items }
}

/// The planted-key attempt. The holder makes up a birth_date item the issuer never signs, and
/// asks for a device key whose x-coordinate is that item's digest. Such a point has no known
/// private key. Returns the forged item and the device key.
pub fn planted_key(forged_birth_date: &Date) -> (Vec<u8>, PublicKey) {
  (0u64..)
    .find_map(|attempt| {
      let random = salt(&format!("planted random {attempt}"));
      let item = item_bytes(99, &random, "birth_date", full_date(forged_birth_date));
      point_with_x(&sha256(&item)).map(|key| (item, key))
    })
    .expect("half of all x-coordinates lie on the curve")
}
