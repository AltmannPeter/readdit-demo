//! The holder's credential taken apart: an ISO/IEC 18013-5 IssuerSigned (base64url) of the
//! nym_auth attestation, as SPEC.md L4.2 reads it.
//!
//! The issuer signed `sig`, the COSE Sig_structure built from the encoded protected header and
//! payload as they stand (L4.2 step 1); the items are the encoded `#6.24(bstr)` entries of the
//! namespace (steps 2 and 3). The rest (MSO docType, device key, validity, the values) is what the
//! holder checks before proving.

use crate::cbor::{self, Key};
use crate::circuit::{BIRTH_DATE, DOC_TYPE, SSC};
use crate::dates::{self, Date, Time};
use crate::x509::PublicKey;

/// An IssuerSigned taken apart.
#[derive(Clone, Debug)]
pub struct Mdoc {
  /// `["Signature1", protected, h'', payload]`, the bytes the issuer signed.
  pub signed: Vec<u8>,
  /// The issuer's signature (r, s).
  pub r: [u8; 32],
  pub s: [u8; 32],
  /// IssuerSignedItemBytes of `birth_date` and of `ssc`, encoded.
  pub birth_item: Vec<u8>,
  pub ssc_item: Vec<u8>,
  /// The Document Signer certificate from `x5chain` (label 33) in the unprotected header.
  pub document_signer: Vec<u8>,
  /// The MSO's docType.
  pub doc_type: String,
  /// The device key bound in the MSO.
  pub device_key: PublicKey,
  pub valid_from: Time,
  pub valid_until: Time,
  pub birth_date: Date,
  pub ssc: [u8; 32],
}

fn bytes32(d: &[u8], p: usize, what: &str) -> Result<[u8; 32], String> {
  let (mt, _, _) = cbor::head(d, p)?;
  if mt != 2 {
    return Err(format!("{what} is not a byte string"));
  }
  cbor::content(d, p)?.try_into().map_err(|_| format!("{what} is not 32 bytes"))
}

fn text<'a>(d: &'a [u8], p: usize, what: &str) -> Result<&'a str, String> {
  let (mt, _, _) = cbor::head(d, p)?;
  if mt != 3 {
    return Err(format!("{what} is not a text string"));
  }
  std::str::from_utf8(cbor::content(d, p)?).map_err(|e| format!("{what}: {e}"))
}

/// The encoded item inside `#6.24(bstr .cbor item)` at `p`.
fn embedded(d: &[u8], p: usize) -> Result<&[u8], String> {
  let inner = cbor::untag(d, p, 24)?;
  let (mt, _, _) = cbor::head(d, inner)?;
  if mt != 2 {
    return Err("tag 24 does not hold a byte string".into());
  }
  let bytes = cbor::content(d, inner)?;
  if cbor::end(bytes, 0)? != bytes.len() {
    return Err("tag 24 holds trailing bytes".into());
  }
  Ok(bytes)
}

fn tdate(d: &[u8], p: usize, what: &str) -> Result<Time, String> {
  let inner = cbor::untag(d, p, 0).map_err(|_| format!("{what} is not a tdate (tag 0)"))?;
  dates::date_time(text(d, inner, what)?)
}

/// Takes an IssuerSigned (base64url) apart.
pub fn parse(issuer_signed: &str) -> Result<Mdoc, String> {
  let d = crate::unb64url("IssuerSigned", issuer_signed)?;
  if cbor::end(&d, 0)? != d.len() {
    return Err("IssuerSigned has trailing bytes".into());
  }
  let auth = cbor::get(&d, 0, Key::Text("issuerAuth")).map_err(|e| format!("IssuerSigned: {e}"))?;
  let [protected, unprotected, payload, signature] = cbor::elements(&d, auth)?[..] else {
    return Err("issuerAuth is not a COSE_Sign1 of 4 elements".into());
  };
  for (p, what) in [(protected, "the protected header"), (payload, "the payload"), (signature, "the signature")] {
    if cbor::head(&d, p)?.0 != 2 {
      return Err(format!("issuerAuth: {what} is not a byte string"));
    }
  }
  let signed =
    [&b"\x84\x6aSignature1"[..], cbor::item(&d, protected)?, b"\x40", cbor::item(&d, payload)?].concat();
  let signature = cbor::content(&d, signature)?;
  if signature.len() != 64 {
    return Err("the issuer signature is not 64 bytes".into());
  }

  // x5chain: one certificate as a bstr, or an array whose first element is the leaf.
  let x5chain = cbor::get(&d, unprotected, Key::Int(33)).map_err(|e| format!("the unprotected header (x5chain): {e}"))?;
  let document_signer = match cbor::head(&d, x5chain)?.0 {
    2 => cbor::content(&d, x5chain)?.to_vec(),
    4 => {
      let first = *cbor::elements(&d, x5chain)?.first().ok_or("x5chain is empty")?;
      cbor::content(&d, first)?.to_vec()
    }
    _ => return Err("x5chain is neither a bstr nor an array".into()),
  };

  // The namespace's items.
  let (mut birth, mut ssc) = (None, None);
  let spaces = cbor::get(&d, 0, Key::Text("nameSpaces")).map_err(|e| format!("IssuerSigned: {e}"))?;
  for (name, list) in cbor::entries(&d, spaces)? {
    let name = text(&d, name, "a namespace")?;
    if name != DOC_TYPE {
      return Err(format!("namespace {name:?} is not {DOC_TYPE}"));
    }
    for entry in cbor::elements(&d, list)? {
      let inner = embedded(&d, entry)?;
      let id = text(inner, cbor::get(inner, 0, Key::Text("elementIdentifier"))?, "elementIdentifier")?;
      let slot = match id {
        BIRTH_DATE => &mut birth,
        SSC => &mut ssc,
        _ => continue,
      };
      if slot.is_some() {
        return Err(format!("item {id} appears twice"));
      }
      *slot = Some(cbor::item(&d, entry)?.to_vec());
    }
  }
  let birth_item = birth.ok_or("no birth_date item")?;
  let ssc_item = ssc.ok_or("no ssc item")?;
  let value = |item: &[u8]| -> Result<Vec<u8>, String> {
    let inner = embedded(item, 0)?;
    Ok(cbor::item(inner, cbor::get(inner, 0, Key::Text("elementValue"))?)?.to_vec())
  };
  let birth_value = value(&birth_item)?;
  let birth_date = dates::date(text(&birth_value, cbor::untag(&birth_value, 0, 1004)?, "birth_date")?)?;
  let ssc_value = bytes32(&value(&ssc_item)?, 0, "ssc")?;

  // The MSO: payload = bstr(#6.24(bstr(MSO))).
  let mso = embedded(cbor::content(&d, payload)?, 0)?;
  let doc_type = text(mso, cbor::get(mso, 0, Key::Text("docType"))?, "docType")?.to_string();
  let info = cbor::get(mso, 0, Key::Text("deviceKeyInfo"))?;
  let key = cbor::get(mso, info, Key::Text("deviceKey"))?;
  let device_key = PublicKey {
    x: bytes32(mso, cbor::get(mso, key, Key::Int(-2))?, "deviceKey x")?,
    y: bytes32(mso, cbor::get(mso, key, Key::Int(-3))?, "deviceKey y")?,
  };
  let validity = cbor::get(mso, 0, Key::Text("validityInfo"))?;

  Ok(Mdoc {
    signed,
    r: signature[..32].try_into().map_err(|_| "r")?,
    s: signature[32..].try_into().map_err(|_| "s")?,
    birth_item,
    ssc_item,
    document_signer,
    doc_type,
    device_key,
    valid_from: tdate(mso, cbor::get(mso, validity, Key::Text("validFrom"))?, "validFrom")?,
    valid_until: tdate(mso, cbor::get(mso, validity, Key::Text("validUntil"))?, "validUntil")?,
    birth_date,
    ssc: ssc_value,
  })
}

impl Mdoc {
  /// Whether the MSO lists both items' digests (the holder's own consistency check; the hash
  /// circuit checks them).
  pub fn digests_listed(&self) -> bool {
    [&self.birth_item, &self.ssc_item].iter().all(|item| {
      let pattern = [&[0x58, 0x20][..], &crate::sha256(item)].concat();
      self.signed.windows(pattern.len()).any(|w| w == pattern)
    })
  }
}
