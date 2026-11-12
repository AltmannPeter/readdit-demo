//! The holder's credential taken apart: an ISO/IEC 18013-5 IssuerSigned (base64url) of the
//! nym_auth attestation.
//!
//! The Sig_structure and the items follow `mdoc()` of the archive's reference program
//! (`vega/reference/src/main.rs`, nymauth-vega), with vega-age's CBOR reader. The reader keeps
//! each item's own encoding, since the issuer's signature and digests cover those bytes.

use vega_age::fixtures::cbor::{Item, Value, int, text};
use vega_age::gadgets::p256::PublicKey;
use vega_age::presentation::{Date, Time};
use vega_age::table::sha256;

use crate::circuit::{BIRTH_DATE, DOC_TYPE, SSC};
use crate::dates;

/// An IssuerSigned taken apart.
#[derive(Clone, Debug)]
pub struct Mdoc {
  /// `["Signature1", protected, h'', payload]`, the bytes the issuer signed.
  pub sig_structure: Vec<u8>,
  /// The issuer's signature (r, s).
  pub r: [u8; 32],
  pub s: [u8; 32],
  /// IssuerSignedItemBytes of each item of the nym_auth namespace, by element identifier.
  pub items: Vec<(String, Vec<u8>)>,
  /// The Document Signer certificate from `x5chain` (label 33) in the unprotected header.
  pub document_signer: Vec<u8>,
  /// The MSO's docType.
  pub doc_type: String,
  /// The device key bound in the MSO.
  pub device_key: PublicKey,
  pub signed: Time,
  pub valid_from: Time,
  pub valid_until: Time,
}

/// The value of a map entry; refuses an item that is not a map (vega-age's reader asserts it).
fn get<'a>(item: &Item<'a>, key: &Value, what: &str) -> Result<Item<'a>, String> {
  if item.major != 5 {
    return Err(format!("{what} is not a map"));
  }
  item.get(key).map_err(|e| format!("{what}: {e}"))
}

/// Element `i` of an array; refuses an item that is not an array.
fn at<'a>(item: &Item<'a>, i: usize, what: &str) -> Result<Item<'a>, String> {
  if item.major != 4 {
    return Err(format!("{what} is not an array"));
  }
  item.at(i).map_err(|e| format!("{what}: {e}"))
}

fn tdate(item: Item) -> Result<Time, String> {
  if item.major != 6 || item.argument != 0 {
    return Err("a validity date is not tag 0".into());
  }
  let inner = item.embedded_tag()?;
  dates::date_time(std::str::from_utf8(inner.content()).map_err(|e| e.to_string())?)
}

/// Reads the inner item of a tag.
trait Tagged<'a> {
  fn embedded_tag(&self) -> Result<Item<'a>, String>;
}

impl<'a> Tagged<'a> for Item<'a> {
  fn embedded_tag(&self) -> Result<Item<'a>, String> {
    if self.major != 6 {
      return Err("not a tag".into());
    }
    let children = self.children();
    children.first().copied().ok_or_else(|| "an empty tag".to_string())
  }
}

fn bytes32(item: Item, what: &str) -> Result<[u8; 32], String> {
  if item.major != 2 {
    return Err(format!("{what} is not a byte string"));
  }
  item.content().try_into().map_err(|_| format!("{what} is not 32 bytes"))
}

/// Takes an IssuerSigned (base64url) apart.
pub fn parse(issuer_signed: &str) -> Result<Mdoc, String> {
  let bytes = crate::unb64url("IssuerSigned", issuer_signed)?;
  let root = Item::read(&bytes)?;
  if root.bytes.len() != bytes.len() {
    return Err("IssuerSigned has trailing bytes".into());
  }
  let auth = get(&root, &text("issuerAuth"), "IssuerSigned")?;
  let (protected, unprotected, payload, signature) =
    (at(&auth, 0, "issuerAuth")?, at(&auth, 1, "issuerAuth")?, at(&auth, 2, "issuerAuth")?, at(&auth, 3, "issuerAuth")?);
  if [protected.major, payload.major, signature.major] != [2, 2, 2] {
    return Err("issuerAuth is not a COSE_Sign1 of byte strings".into());
  }
  let signature = signature.content();
  let sig_structure = Value::Array(vec![
    text("Signature1"),
    Value::Bytes(protected.content().to_vec()),
    Value::Bytes(vec![]),
    Value::Bytes(payload.content().to_vec()),
  ])
  .encode();
  if signature.len() != 64 {
    return Err("the issuer signature is not 64 bytes".into());
  }

  // x5chain: one certificate as a bstr, or an array whose first element is the leaf.
  let x5chain = get(&unprotected, &int(33), "the unprotected header (x5chain, label 33)")?;
  let document_signer = match x5chain.major {
    2 => x5chain.content().to_vec(),
    4 => at(&x5chain, 0, "x5chain")?.content().to_vec(),
    _ => return Err("x5chain is neither a bstr nor an array".into()),
  };

  let mut items = Vec::new();
  let name_spaces = get(&root, &text("nameSpaces"), "IssuerSigned")?;
  for entry in name_spaces.children().chunks(2) {
    let [name, list] = entry else { return Err("nameSpaces is not a map".into()) };
    if name.content() != DOC_TYPE.as_bytes() {
      return Err(format!("namespace {:?} is not {DOC_TYPE}", String::from_utf8_lossy(name.content())));
    }
    if list.major != 4 {
      return Err("a namespace's items are not an array".into());
    }
    for item in list.children() {
      let id = get(&item.embedded()?, &text("elementIdentifier"), "IssuerSignedItem")?;
      let id = String::from_utf8(id.content().to_vec()).map_err(|e| e.to_string())?;
      items.push((id, item.bytes.to_vec()));
    }
  }

  // The MSO: payload = bstr(#6.24(bstr(MSO))).
  let mso_bytes = Item::read(payload.content())?.embedded()?;
  let doc_type = String::from_utf8(get(&mso_bytes, &text("docType"), "MSO")?.content().to_vec()).map_err(|e| e.to_string())?;
  let key = get(&get(&mso_bytes, &text("deviceKeyInfo"), "MSO")?, &text("deviceKey"), "deviceKeyInfo")?;
  let device_key = PublicKey {
    x: bytes32(get(&key, &int(-2), "deviceKey")?, "deviceKey x")?,
    y: bytes32(get(&key, &int(-3), "deviceKey")?, "deviceKey y")?,
  };
  let validity = get(&mso_bytes, &text("validityInfo"), "MSO")?;

  Ok(Mdoc {
    sig_structure,
    r: signature[..32].try_into().map_err(|_| "r")?,
    s: signature[32..].try_into().map_err(|_| "s")?,
    items,
    document_signer,
    doc_type,
    device_key,
    signed: tdate(get(&validity, &text("signed"), "validityInfo")?)?,
    valid_from: tdate(get(&validity, &text("validFrom"), "validityInfo")?)?,
    valid_until: tdate(get(&validity, &text("validUntil"), "validityInfo")?)?,
  })
}

impl Mdoc {
  /// IssuerSignedItemBytes of an element.
  pub fn item(&self, id: &str) -> Result<&[u8], String> {
    let mut found = self.items.iter().filter(|(name, _)| name == id);
    match (found.next(), found.next()) {
      (Some((_, bytes)), None) => Ok(bytes),
      (None, _) => Err(format!("no item {id}")),
      (Some(_), Some(_)) => Err(format!("item {id} appears twice")),
    }
  }

  fn element_value(&self, id: &str) -> Result<Vec<u8>, String> {
    let bytes = self.item(id)?;
    let item = Item::read(bytes)?;
    Ok(get(&item.embedded()?, &text("elementValue"), "IssuerSignedItem")?.bytes.to_vec())
  }

  /// `birth_date`: tag 1004 on a full-date.
  pub fn birth_date(&self) -> Result<Date, String> {
    let value = self.element_value(BIRTH_DATE)?;
    let item = Item::read(&value)?;
    if item.major != 6 || item.argument != 1004 {
      return Err("birth_date is not tag 1004".into());
    }
    let inner = item.embedded_tag()?;
    dates::date(std::str::from_utf8(inner.content()).map_err(|e| e.to_string())?)
  }

  /// `ssc`: a bstr of 32 bytes.
  pub fn ssc(&self) -> Result<[u8; 32], String> {
    let value = self.element_value(SSC)?;
    bytes32(Item::read(&value)?, "ssc")
  }

  /// `bsc` (rulebook v0.5): a bstr of 32 bytes, SHA-256(secret_seed ‖ birth_date).
  pub fn bsc(&self) -> Result<[u8; 32], String> {
    let value = self.element_value(crate::bsc::BSC)?;
    bytes32(Item::read(&value)?, "bsc")
  }

  /// Whether the MSO lists each item's digest (the holder's own consistency check; the circuit
  /// checks the two it reads).
  pub fn digests_listed(&self) -> bool {
    self.items.iter().all(|(_, bytes)| {
      let pattern = [&[0x58, 0x20][..], &sha256(bytes)].concat();
      self.sig_structure.windows(pattern.len()).any(|w| w == pattern)
    })
  }
}
