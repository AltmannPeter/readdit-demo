//! The holder's credential: an ISO/IEC 18013-5 IssuerSigned structure of the nym_auth attestation
//! (docType `eu.europa.ec.eudi.nym_auth.1`, namespace of the same name, items `bsc` and `psc`).
//!
//! Parsing finds what the hash circuit reads: the COSE Sig_structure the issuer signed, the
//! positions in it of the docType, the device key, the validity and the listed digest of the
//! `bsc` item, and the `bsc` item's encoding with the positions of its identifier and value. The
//! circuit checks every byte it reads at these positions, so this parsing matters for completeness
//! only: a wrong position yields a witness the circuit refuses, never a false proof.

use crate::cbor::{self, Item, Value};
use crate::Error;
use sha2::{Digest, Sha256};

pub const DOC_TYPE: &str = "eu.europa.ec.eudi.nym_auth.1";
pub const NAMESPACE: &str = "eu.europa.ec.eudi.nym_auth.1";

/// The fixed sizes the circuits are built for (the rulebook's compact profile): the
/// Sig_structure in 7 SHA-256 blocks, the bsc item in 2.
pub const SIGNED_BLOCKS: usize = 7;
pub const ITEM_BLOCKS: usize = 2;

pub struct Parsed {
    /// ["Signature1", protected, h'', payload], as the issuer signed it.
    pub sig_structure: Vec<u8>,
    /// The issuer's signature r || s.
    pub issuer_sig: [u8; 64],
    /// The device key's coordinates, big-endian.
    pub device_x: [u8; 32],
    pub device_y: [u8; 32],
    /// The bsc item's IssuerSignedItemBytes (tag 24 on its encoding), as the MSO digests it.
    pub bsc_item: Vec<u8>,
    /// The commitment bsc, the item's value.
    pub bsc: [u8; 32],
    /// Offsets in the Sig_structure.
    pub doc_type_at: usize,
    pub device_key_at: usize,
    pub valid_from_at: usize,
    pub valid_until_at: usize,
    pub bsc_digest_at: usize,
    /// Offsets in the bsc item.
    pub bsc_identifier_at: usize,
    pub bsc_value_at: usize,
}

/// The exact docType pattern the circuit compares: the key `docType`, then the docType as CBOR
/// text.
pub fn doc_type_pattern(doc_type: &str) -> Vec<u8> {
    let mut p = vec![0x67];
    p.extend_from_slice(b"docType");
    cbor::put_text(&mut p, doc_type);
    p
}

pub const DEVICE_KEY: &[u8] = b"\x69deviceKey\xa4\x01\x02\x20\x01\x21\x58\x20";
pub const DEVICE_KEY_Y: &[u8] = b"\x22\x58\x20";
pub const VALID_FROM: &[u8] = b"\x69validFrom\xc0\x74";
pub const VALID_UNTIL: &[u8] = b"\x6avalidUntil\xc0\x74";
pub const BSC_IDENTIFIER: &[u8] = b"\x71elementIdentifier\x63bsc";
pub const BSTR32_VALUE: &[u8] = b"\x6celementValue\x58\x20";

/// The one position of `pat` in `hay`.
fn unique(hay: &[u8], pat: &[u8], what: &'static str) -> Result<usize, Error> {
    let mut found = None;
    for i in 0..=hay.len().saturating_sub(pat.len()) {
        if hay.len() >= pat.len() && &hay[i..i + pat.len()] == pat {
            if found.is_some() {
                return Err(Error::Credential(what));
            }
            found = Some(i);
        }
    }
    found.ok_or(Error::Credential(what))
}

pub fn parse(issuer_signed: &[u8], doc_type: &str) -> Result<Parsed, Error> {
    let root = cbor::decode(issuer_signed)?;
    let auth = root
        .get("issuerAuth")
        .and_then(Item::as_array)
        .ok_or(Error::Credential("no issuerAuth COSE_Sign1"))?;
    if auth.len() != 4 {
        return Err(Error::Credential("issuerAuth is not a COSE_Sign1"));
    }
    let protected = auth[0].as_bytes().ok_or(Error::Credential("COSE protected header"))?;
    let payload = auth[2].as_bytes().ok_or(Error::Credential("COSE payload"))?;
    let sig: [u8; 64] = auth[3]
        .as_bytes()
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Credential("issuer signature is not 64 bytes"))?;

    let mut ss = Vec::with_capacity(payload.len() + 32);
    cbor::put_array(&mut ss, 4);
    cbor::put_text(&mut ss, "Signature1");
    cbor::put_bytes(&mut ss, protected);
    cbor::put_bytes(&mut ss, &[]);
    cbor::put_bytes(&mut ss, payload);

    // The MSO: tag 24 on a bstr holding the map.
    let tagged = cbor::decode(payload)?;
    let mso_bytes = match &tagged.value {
        Value::Tag(24, inner) => inner.as_bytes().ok_or(Error::Credential("MSO is not a bstr"))?,
        _ => return Err(Error::Credential("payload is not tag 24")),
    };
    let mso = cbor::decode(mso_bytes)?;
    if mso.get("docType").and_then(Item::as_text) != Some(doc_type) {
        return Err(Error::Credential("MSO docType is not the requested one"));
    }
    let dk = mso
        .get("deviceKeyInfo")
        .and_then(|d| d.get("deviceKey"))
        .ok_or(Error::Credential("no deviceKey"))?;
    let device_x: [u8; 32] = dk
        .get_int(-2)
        .and_then(Item::as_bytes)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Credential("device key x"))?;
    let device_y: [u8; 32] = dk
        .get_int(-3)
        .and_then(Item::as_bytes)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Credential("device key y"))?;

    // The bsc item, in the namespace's list.
    let items = root
        .get("nameSpaces")
        .and_then(|n| n.get(NAMESPACE))
        .and_then(Item::as_array)
        .ok_or(Error::Credential("no nym_auth namespace"))?;
    let mut bsc_item = None;
    for it in items {
        let enc = &issuer_signed[it.start..it.end];
        if let Value::Tag(24, inner) = &it.value {
            if let Some(b) = inner.as_bytes() {
                if let Ok(m) = cbor::decode(b) {
                    if m.get("elementIdentifier").and_then(Item::as_text) == Some("bsc") {
                        let v: [u8; 32] = m
                            .get("elementValue")
                            .and_then(Item::as_bytes)
                            .and_then(|x| x.try_into().ok())
                            .ok_or(Error::Credential("bsc is not a 32-byte bstr"))?;
                        bsc_item = Some((enc.to_vec(), v));
                    }
                }
            }
        }
    }
    let (bsc_item, bsc) = bsc_item.ok_or(Error::Credential("no bsc item"))?;

    let pattern = doc_type_pattern(doc_type);
    let digest = Sha256::digest(&bsc_item);
    let mut listed = vec![0x58, 0x20];
    listed.extend_from_slice(&digest);
    let parsed = Parsed {
        doc_type_at: unique(&ss, &pattern, "docType pattern not found once")?,
        device_key_at: unique(&ss, DEVICE_KEY, "deviceKey not found once")?,
        valid_from_at: unique(&ss, VALID_FROM, "validFrom not found once")?,
        valid_until_at: unique(&ss, VALID_UNTIL, "validUntil not found once")?,
        bsc_digest_at: unique(&ss, &listed, "bsc digest not listed once")?,
        bsc_identifier_at: unique(&bsc_item, BSC_IDENTIFIER, "bsc identifier")?,
        bsc_value_at: unique(&bsc_item, BSTR32_VALUE, "bsc value")?,
        sig_structure: ss,
        issuer_sig: sig,
        device_x,
        device_y,
        bsc_item,
        bsc,
    };
    // The device key's coordinates are where the window reads them.
    let x_at = parsed.device_key_at + DEVICE_KEY.len();
    if parsed.sig_structure[x_at..x_at + 32] != parsed.device_x
        || parsed.sig_structure[x_at + 32..x_at + 35] != *DEVICE_KEY_Y
        || parsed.sig_structure[x_at + 35..x_at + 67] != parsed.device_y
    {
        return Err(Error::Credential("device key is not the COSE_Key the circuit reads"));
    }
    if crate::sha::pad(&parsed.sig_structure).len() != 64 * SIGNED_BLOCKS {
        return Err(Error::Credential("the Sig_structure is not 7 SHA-256 blocks"));
    }
    if crate::sha::pad(&parsed.bsc_item).len() != 64 * ITEM_BLOCKS {
        return Err(Error::Credential("the bsc item is not 2 SHA-256 blocks"));
    }
    Ok(parsed)
}
