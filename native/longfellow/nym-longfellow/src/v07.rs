//! The rulebook v0.7 Longfellow circuits: the v0.7 decoy-digest layout (namespace
//! `eu.nym_auth.v1`, the device key compressed, bsc and psc as two AES-128 blocks each, the
//! pseudonym AES-128 under secret_seed), run by the `nym-auth-zk-v07` crate, driven from Community's
//! own values. v0.7 keeps v0.5's request and presentation rules except the pseudonym's `prf`,
//! `aes-128` ([`crate::request::Rulebook::V07`]). REFERENCE ADAPTER (shipped with the circuit package
//! nym-auth-longfellow-v07-v1): decoy.rs with the crate swapped. It maps what
//! [`crate::request::statement_for`] has already validated, the handover from the session store,
//! and the Document Signer's key onto `nym_auth_zk_v07::Request`. `nym-auth-zk-v07` computes every
//! public input from that `Request` (E and C from the range and the UTC date of `proof_time`,
//! verifier_input and H, e2, the transcript seed); never pass it bounds or digests computed here.

use nym_auth_zk_v07 as v5;

use crate::handover::Handover;
use crate::request::RequestObject;
use crate::x509::PublicKey;

/// The circuits are the archive compiled into `nym-auth-zk-v07` (`nym_auth_zk_v07::zk::CIRCUITS`,
/// the file `nym-auth-zk-v07/circuits/nym_auth_mdoc_v07.lfa2.zst` byte for byte). Their system_id is
/// `urn:circuits:sha256:` and that archive's SHA-256 ([`system_id`]); re-compressing the archive
/// would change it.
pub fn system_id() -> String {
  v5::system_id()
}

/// The archive's SHA-256, as the registry's `artifact.sha256` and the services' `info` report it.
pub fn archive_sha256() -> [u8; 32] {
  crate::sha256(v5::zk::CIRCUITS)
}

/// The circuits, each checked against its Longfellow id.
pub fn circuits() -> Result<v5::Circuits, String> {
  v5::Circuits::load().map_err(|e| format!("{e:?}"))
}

fn load<T>(make: impl FnOnce(v5::Circuits) -> T) -> Result<crate::v05::Loaded<T>, String> {
  let t = std::time::Instant::now();
  let circuits = circuits()?;
  let counts = [
    (circuits.hash.raw.ninput, circuits.hash.raw.npublic_input),
    (circuits.sig.raw.ninput, circuits.sig.raw.npublic_input),
  ];
  Ok(crate::v05::Loaded { side: make(circuits), sha256: archive_sha256(), load_ms: crate::measure::ms(t), counts })
}

/// The v0.7 circuits for the prover, loaded once (as [`crate::v05::load_prover`]).
pub fn load_prover() -> Result<crate::v05::Loaded<v5::Prover>, String> {
  load(v5::Prover::new)
}

/// The v0.7 circuits for the verifier, loaded once (as [`crate::v05::load_verifier`]).
pub fn load_verifier() -> Result<crate::v05::Loaded<v5::Verifier>, String> {
  load(v5::Verifier::new)
}

/// The session the device signature binds. Community invokes the wallet by QR code, so
/// OpenID4VP 1.0 B.2.6.1: `OpenID4VPHandover` over [client_id, nonce, jwk_thumbprint, response_uri].
pub fn session(h: &Handover) -> Result<v5::Session, String> {
  Ok(v5::Session::Redirect {
    client_id: h.client_id.clone(),
    nonce: h.nonce.clone(),
    jwk_thumbprint: h.thumbprint()?,
    response_uri: h.response_uri.clone(),
  })
}

/// The `range` of the v0.5/v0.7 `age_check` in credential query `query_id`, if one is requested.
/// Call after `statement_for` has accepted the request (it refuses a malformed one).
pub fn age_range(request: &RequestObject, query_id: &str) -> Result<Option<v5::AgeRange>, String> {
  let q = request.dcql_query.credentials.iter().find(|q| q.id == query_id).ok_or("no such credential query")?;
  let Some(item) = q.req.iter().find(|r| r.fn_id == "age_check") else { return Ok(None) };
  let range = item.params.get("range").and_then(|v| v.as_str()).ok_or("age_check without range")?;
  v5::AgeRange::parse(range).map(Some).map_err(|e| format!("age_check.range: {e:?}"))
}

/// The statement both sides prove and verify: the issuer key from the Document Signer
/// certificate, `proof_time` as presented (the verifier checks its tolerance itself), the age
/// range, verifier_id = client_id (the x509_san_dns form), and the redirect session.
pub fn request(
  issuer_key: &PublicKey,
  proof_time: &str,
  request: &RequestObject,
  query_id: &str,
  handover: &Handover,
) -> Result<v5::Request, String> {
  Ok(v5::Request {
    issuer_key: (issuer_key.x, issuer_key.y),
    proof_time: proof_time.to_string(),
    age_range: age_range(request, query_id)?,
    verifier_id: request.client_id.clone(),
    session: session(handover)?,
  })
}

/// The prover's refusal for a `nym_auth_zk_v07::Error` from `prebuild` or `prove_prebuilt`. Of the
/// `Holder` reasons, a birth date outside the range and a credential not valid at proof_time are
/// predicates that do not hold (`unsatisfiable`: the wallet answers `access_denied`); the others
/// (issuer or device signature, the opening of bsc, the birth date's form) are inconsistent holder
/// material (`bad_credential`), as is a credential the circuits cannot read.
pub fn prover_refusal(e: &v5::Error) -> crate::error::Refusal {
  use crate::error::Refusal;
  match e {
    v5::Error::Holder(m @ ("birth_date is outside the age range" | "the credential is not valid at proof_time")) => {
      Refusal::unsatisfiable(*m)
    }
    v5::Error::Holder(m) | v5::Error::Credential(m) => Refusal::bad_credential(*m),
    v5::Error::Request(m) => Refusal::bad_request(*m),
    other => Refusal::bad_request(format!("{other:?}")),
  }
}

/// Which circuit a `nym_auth_zk_v07::Error::Proof` names, for the verifier's `proof_invalid.input`
/// (`None`: the proof bytes do not decode, `proof_encoding`).
pub fn failing_circuit(e: &v5::Error) -> Option<&'static str> {
  match e {
    v5::Error::Proof(m) if m.contains("does not verify") && m.starts_with("hash") => Some("hash"),
    v5::Error::Proof(m) if m.contains("does not verify") => Some("signature"),
    _ => None,
  }
}

/// The artifact's name, as the registry names it.
pub const ARTIFACT: &str = "nym_auth_mdoc_v07.lfa2.zst";

/// The v0.7 circuits' public inputs, grouped by input, with the elements each takes in the hash
/// circuit (GF(2^128)) and in the signature circuit (P-256), in circuit order (the package's
/// INTEGRATION.md §7). Each circuit's constant 1 is left out. Hash: 266 + 1 = 267; signature:
/// 898 + 1 = 899. Against v0.6: `pseudonym.nym_block` (H, the block the pseudonym encrypts) in
/// place of `pseudonym.verifier_input`, and four MAC tags in place of six (the device key's x only).
pub const PUBLIC_INPUTS: [(&str, usize, usize); 9] = [
  ("proof_time", 1, 0),
  ("pseudonym.nym_block", 256, 0),
  ("results.nym", 2, 0),
  ("age_check.ge", 1, 0),
  ("age_check.le", 1, 0),
  ("mac.challenge", 1, 128),
  ("mac.tags", 4, 512),
  ("issuer_key_set", 0, 2),
  ("session_transcript", 0, 256),
];

/// What the prover's checks read from a v0.7 credential besides
/// `nym_auth_zk_v07::mdoc::parse` (which refuses any deviation from the layout): the Document
/// Signer certificate (x5chain) and the validity (fixed offsets of the Sig_structure).
pub struct Credential {
  pub parsed: v5::mdoc::Parsed,
  pub document_signer: Vec<u8>,
  pub valid_from: crate::dates::Time,
  pub valid_until: crate::dates::Time,
}

pub fn credential(issuer_signed: &[u8]) -> Result<Credential, String> {
  let parsed = v5::mdoc::parse(issuer_signed).map_err(|e| match e {
    v5::Error::Credential(m) => format!("not the v0.7 layout the circuits read: {m}"),
    e => format!("{e:?}"),
  })?;
  // The layout fixes the head: a1 6a "issuerAuth" 84 43 a1 01 26 a1 18 21, then the x5chain bstr.
  let h = 20;
  let (len, at) = match issuer_signed[h] {
    0x58 => (usize::from(issuer_signed[h + 1]), h + 2),
    _ => (usize::from(issuer_signed[h + 1]) << 8 | usize::from(issuer_signed[h + 2]), h + 3),
  };
  let der = issuer_signed[at..at + len].to_vec();
  let tdate = |at: usize, what: &str| -> Result<crate::dates::Time, String> {
    let t = std::str::from_utf8(&parsed.sig_structure[at..at + 20]).map_err(|_| format!("{what}: not text"))?;
    crate::dates::date_time(t).map_err(|e| format!("{what}: {e}"))
  };
  let valid_from = tdate(v5::mdoc::VALID_FROM_AT, "validFrom")?;
  let valid_until = tdate(v5::mdoc::VALID_UNTIL_AT, "validUntil")?;
  Ok(Credential { parsed, document_signer: der, valid_from, valid_until })
}
