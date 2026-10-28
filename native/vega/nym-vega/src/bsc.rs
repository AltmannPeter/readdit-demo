//! The rulebook v0.5 Vega circuits (`vega_age::bsc`, the `bsc` attestation), driven from
//! Community's own values. REFERENCE ADAPTER (shipped with the circuit package): it maps what
//! [`crate::request::statement_for`] has already validated, the Document Signer's key and the
//! holder's material onto `vega_age::bsc`, and reads a verdict back.
//!
//! The circuits as data are `circuits/mdoc-bsc/shapes.zst`; their system_id is
//! `urn:circuits:sha256:` and that file's SHA-256 ([`system_id`]). Ship the file byte for byte:
//! compressing the same shapes again with another zstd can give other bytes, and another id.

use sha2::{Digest, Sha256};
use vega_age::app::{self, ProverKey, Rejection, VerifierKey};
use vega_age::bsc::{BSC_MDOC, BscCore, BscPresentation, BscPublic, BscWitness, DOC_TYPE};
use vega_age::gadgets::p256::{PublicKey, Signature};
use vega_age::presentation::Time;
use vega_age::pseudonym;
use vega_age::request::Pattern;

use crate::mdoc::Mdoc;
use crate::request::Statement;

/// The element the circuits read: the commitment SHA-256(secret_seed ‖ birth_date).
pub const BSC: &str = "bsc";

/// The core's public values in order, grouped by the input they encode, with the number of field
/// elements each takes. 15 values: the verifier names the first 13, the proof reports the last 2.
pub const PUBLIC_INPUTS: [(&str, usize); 8] = [
  ("issuer_key_set", 2),
  ("age_check.ge", 1),
  ("age_check.le", 1),
  ("proof_time", 1),
  ("session_transcript", 2),
  ("doctype", 3),
  ("pseudonym.verifier_input", 3),
  ("results.nym", 2),
];

/// The input that the core public value at `index` encodes.
pub fn input_at(index: usize) -> Option<&'static str> {
  let mut start = 0;
  for (name, count) in PUBLIC_INPUTS {
    if index < start + count {
      return Some(name);
    }
    start += count;
  }
  None
}

/// The registry's system_id of the circuits in `shapes_zst` (the file's bytes as shipped).
pub fn system_id(shapes_zst: &[u8]) -> String {
  format!("urn:circuits:sha256:{}", hex::encode(Sha256::digest(shapes_zst)))
}

/// Both keys from the circuits as data (`shapes.zst`, decompressed), in the v0.5 layout.
pub fn keys(shapes_zst: &[u8]) -> Result<(ProverKey, VerifierKey), String> {
  let raw = zstd::stream::decode_all(shapes_zst).map_err(|e| format!("zstd: {e}"))?;
  app::setup_from_shapes_in(&BSC_MDOC, &raw).map_err(|e| format!("keys: {e:?}"))
}

/// The values the verifier names, and the pseudonym (the prover's; the verifier passes the
/// presentation's `results` value, which the proof must report). E and C are the statement's
/// (`dates::range_bounds` of the request's range on the UTC date of `proof_time`); a missing bound
/// is the widest (0, 99999999).
pub fn public(
  issuer_key: PublicKey,
  s: &Statement,
  proof_time: Time,
  pseudonym: [u8; 32],
) -> Result<BscPublic, String> {
  Ok(BscPublic {
    issuer_key,
    born_from: s.age.born_from,
    born_by: s.age.born_by,
    now: proof_time,
    challenge: s.challenge,
    doc_type: Pattern::doc_type(DOC_TYPE)?,
    verifier_input: s.verifier_input,
    pseudonym,
  })
}

/// The prover's witness of a v0.5 credential: its Sig_structure, issuer signature and `bsc` item,
/// the holder's secret_seed and birth_date (`YYYY-MM-DD`), for the statement's verifier_input.
/// Refuses a credential outside the compact profile's sizes.
pub fn witness(
  m: &Mdoc,
  issuer_key: PublicKey,
  secret_seed: &[u8; 16],
  birth_date: &[u8; 10],
  s: &Statement,
) -> Result<BscWitness, String> {
  let item = m.item(BSC)?;
  let signature = Signature::from_rs(&m.r, &m.s);
  BscWitness::new(
    &m.sig_structure,
    item,
    secret_seed,
    birth_date,
    &s.verifier_input,
    issuer_key,
    signature,
  )
}

/// The core of one presentation.
pub fn core(w: BscWitness, public: BscPublic, device_signature: &[u8; 64]) -> BscCore {
  let device_signature = Signature::from_rs(
    device_signature[..32].try_into().expect("32 bytes"),
    device_signature[32..].try_into().expect("32 bytes"),
  );
  BscCore {
    witness: Some(std::sync::Arc::new(w)),
    presentation: Some(BscPresentation { public, device_signature }),
  }
}

/// The SHA-256(secret_seed ‖ birth_date) the credential's `bsc` must hold (the holder's own check).
pub fn commitment(secret_seed: &[u8; 16], birth_date: &[u8; 10]) -> [u8; 32] {
  Sha256::digest(vega_age::bsc::opening(secret_seed, birth_date)).into()
}

/// The pseudonym the holder presents to the statement's verifier.
pub fn pseudonym_for(secret_seed: &[u8; 16], s: &Statement) -> [u8; 32] {
  pseudonym::pseudonym(secret_seed, &s.verifier_input)
}

/// Accepts a proof for the verifier's own values; returns the pseudonym it reports, or the
/// refusal: `(code, input)` as the verifier names them.
pub fn accept(
  vk: &VerifierKey,
  proof: &app::Proof,
  public: &BscPublic,
) -> Result<[u8; 32], (&'static str, Option<&'static str>)> {
  let expected = public.named_values();
  match app::accept_pseudonym(&BSC_MDOC, vk, proof, &expected) {
    Ok(nym) if nym == public.pseudonym => Ok(nym),
    Ok(_) => Err(("public_input", Some("results.nym"))),
    Err(Rejection::Invalid(_)) | Err(Rejection::Position { .. }) => Err(("proof_invalid", None)),
    Err(Rejection::PublicValues { reported }) => {
      let index =
        (0..expected.len()).find(|&i| reported.get(i) != expected.get(i)).unwrap_or(expected.len());
      Err(("public_input", input_at(index)))
    }
  }
}
