//! The rulebook v0.5 Longfellow circuits (`bsc`), run by the `nym-auth-zk` crate, driven from
//! Community's own values. REFERENCE ADAPTER (shipped with the circuit package): it maps what
//! [`crate::request::statement_for`] has already validated, the handover from the session store,
//! and the Document Signer's key onto `nym_auth_zk::Request`. `nym-auth-zk` computes every public
//! input from that `Request` (E and C from the range and the UTC date of `proof_time`,
//! verifier_input, e2, the transcript seed); never pass it bounds or digests computed here.

use nym_auth_zk as v5;

use crate::handover::Handover;
use crate::request::RequestObject;
use crate::x509::PublicKey;

/// The circuits are the archive compiled into `nym-auth-zk` (`nym_auth_zk::zk::CIRCUITS`, the
/// file `nym-auth-zk/circuits/nym_auth_mdoc_bsc.lfa2.zst` byte for byte). Their system_id is
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

/// The `range` of the v0.5 `age_check` in credential query `query_id`, if one is requested.
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

/// The prover's refusal for a `nym_auth_zk::Error` from `prebuild` or `prove_prebuilt`. Of the
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

/// Which circuit a `nym_auth_zk::Error::Proof` names, for the verifier's `proof_invalid.input`
/// (`None`: the proof bytes do not decode, `proof_encoding`).
pub fn failing_circuit(e: &v5::Error) -> Option<&'static str> {
  match e {
    v5::Error::Proof(m) if m.contains("does not verify") && m.starts_with("hash") => Some("hash"),
    v5::Error::Proof(m) if m.contains("does not verify") => Some("signature"),
    _ => None,
  }
}
