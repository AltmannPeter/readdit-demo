//! Rulebook v0.5 on Longfellow: the `bsc` circuits of `nym-auth-zk` (Peter's circuit package,
//! `nym-auth-longfellow-v1`), next to the v0.4 circuits of `circuits/mdoc`. The crate is delivered
//! as is and pinned in `VENDOR-SHA256SUMS`; [`crate::bsc`] (the package's adapter) maps the site's
//! request, handover and Document Signer key onto `nym_auth_zk::Request`, and the crate computes
//! every public input from that (E and C from the range and the UTC date of `proof_time`,
//! verifier_input, e2, the transcript seed).
//!
//! This module adds what the prover's holder-side checks need from a v0.5 credential (the
//! Document Signer certificate in x5chain, the validity in the MSO), the circuits' registry
//! values, and the loaded circuits.

use std::time::Instant;

use nym_auth_zk as v5;
use v5::cbor::{self, Item, Value};

use crate::dates::{self, Time};
use crate::measure::ms;

/// The v0.5 circuits' artifact, as the registry names it (`shared/registry/circuits.ts`).
pub const ARTIFACT: &str = "nym_auth_mdoc_bsc.lfa2.zst";

/// The public inputs of the v0.5 circuits, grouped by the input they encode, with the elements
/// each takes in the hash circuit (GF(2^128)) and in the signature circuit (P-256), in circuit
/// order (the package's INTEGRATION.md §7). Each circuit's constant 1 is left out. Hash: 277 + 1 =
/// 278 public slots; signature: 1154 + 1 = 1155.
pub const PUBLIC_INPUTS: [(&str, usize, usize); 10] = [
  ("doctype", 8, 0),
  ("proof_time", 2, 0),
  ("pseudonym.verifier_input", 256, 0),
  ("results.nym", 2, 0),
  ("age_check.ge", 1, 0),
  ("age_check.le", 1, 0),
  ("mac.challenge", 1, 128),
  ("mac.tags", 6, 768),
  ("issuer_key_set", 0, 2),
  ("session_transcript", 0, 256),
];

/// The v0.5 circuits, loaded once: the archive compiled into `nym-auth-zk` (the same bytes as
/// `nym-auth-zk/circuits/nym_auth_mdoc_bsc.lfa2.zst`), each circuit checked against its
/// Longfellow id.
pub struct Loaded<T> {
  pub side: T,
  /// SHA-256 of the archive, which the registry pins.
  pub sha256: [u8; 32],
  pub load_ms: f64,
}

fn load<T>(make: impl FnOnce(v5::Circuits) -> T) -> Result<Loaded<T>, String> {
  let t = Instant::now();
  let circuits = crate::bsc::circuits(v5::zk::CIRCUITS)?;
  Ok(Loaded { side: make(circuits), sha256: crate::sha256(v5::zk::CIRCUITS), load_ms: ms(t) })
}

pub fn load_prover() -> Result<Loaded<v5::Prover>, String> {
  load(v5::Prover::new)
}

pub fn load_verifier() -> Result<Loaded<v5::Verifier>, String> {
  load(v5::Verifier::new)
}

/// What the prover's checks read from a v0.5 credential besides `nym_auth_zk::mdoc::parse`.
pub struct Credential {
  pub parsed: v5::mdoc::Parsed,
  /// The Document Signer certificate (x5chain, label 33), DER.
  pub document_signer: Vec<u8>,
  pub valid_from: Time,
  pub valid_until: Time,
}

/// The 20-character tdate after `pattern` in the Sig_structure.
fn tdate_at(ss: &[u8], at: usize, pattern: &[u8], what: &str) -> Result<Time, String> {
  let start = at + pattern.len();
  let text = ss.get(start..start + 20).ok_or_else(|| format!("{what}: short"))?;
  let text = std::str::from_utf8(text).map_err(|_| format!("{what}: not text"))?;
  dates::date_time(text).map_err(|e| format!("{what}: {e}"))
}

/// Takes a v0.5 IssuerSigned apart: what the circuits read (`nym_auth_zk::mdoc::parse`, which
/// refuses anything but the compact profile), the Document Signer certificate and the validity.
pub fn credential(issuer_signed: &[u8]) -> Result<Credential, String> {
  let parsed = v5::mdoc::parse(issuer_signed, v5::mdoc::DOC_TYPE).map_err(|e| match e {
    v5::Error::Credential(m) => format!("not the v0.5 compact profile the circuits read: {m}"),
    e => format!("{e:?}"),
  })?;
  let root = cbor::decode(issuer_signed).map_err(|e| format!("{e:?}"))?;
  let auth = root.get("issuerAuth").and_then(Item::as_array).ok_or("no issuerAuth")?;
  let unprotected = auth.get(1).ok_or("no unprotected header")?;
  let x5chain = unprotected.get_int(33).ok_or("no x5chain (label 33)")?;
  let der = match &x5chain.value {
    Value::Bytes(b) => b.clone(),
    Value::Array(a) => a.first().and_then(Item::as_bytes).ok_or("x5chain is empty")?.to_vec(),
    _ => return Err("x5chain is not a certificate".into()),
  };
  let ss = &parsed.sig_structure;
  let valid_from = tdate_at(ss, parsed.valid_from_at, v5::mdoc::VALID_FROM, "validFrom")?;
  let valid_until = tdate_at(ss, parsed.valid_until_at, v5::mdoc::VALID_UNTIL, "validUntil")?;
  Ok(Credential { parsed, document_signer: der, valid_from, valid_until })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn public_inputs_fill_the_public_slots() {
    let hash: usize = PUBLIC_INPUTS.iter().map(|p| p.1).sum();
    let sig: usize = PUBLIC_INPUTS.iter().map(|p| p.2).sum();
    assert_eq!((hash + 1, sig + 1), (278, 1155));
  }

  #[test]
  fn reads_the_rulebook_fixture() {
    let p = format!("{}/../../../profiles/nym-auth-v0.5/test-vectors/nym_auth_mdoc/issuer_signed.cbor", env!("CARGO_MANIFEST_DIR"));
    let c = credential(&std::fs::read(p).unwrap()).unwrap();
    assert_eq!(c.valid_from.text(), "2026-10-27T00:00:00Z");
    assert_eq!(c.valid_until.text(), "2027-10-27T00:00:00Z");
    assert!(crate::x509::parse(&c.document_signer).is_ok());
  }
}
