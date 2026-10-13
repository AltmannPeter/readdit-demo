//! Prover and verifier of the nym_auth statement (age range and `pseudonym-v1-sha256`,
//! configuration `known-offender-matching-ssc`) with Vega, as the Readdit demo runs them.
//!
//! The circuits and the witness builder are the nym-auth-circuits archive's `vega-age`, vendored
//! unchanged. This crate adds what an OpenID4VP presentation needs around them:
//!
//! | Module | Role |
//! | --- | --- |
//! | [`circuit`] | The registry values: circuit id, proof system, public-input order |
//! | [`handover`] | SessionTranscript `[null, null, OpenID4VPHandover]` (OpenID4VP 1.0, B.2.6.1) and the device challenge |
//! | [`request`] | The verifier's values from the signed Request Object and the handover (rulebook, "Verification") |
//! | [`dates`] | Full-dates, date-times and the clock |
//! | [`mdoc`] | The holder's IssuerSigned taken apart |
//! | [`x509`] | The Document Signer certificate of `issuer_key_set` |
//! | [`presentation`] | `CircuitZkPresentation` in CBOR (rulebook, "Presentation encoding") |
//! | [`keys`] | The keys from `shapes.zst` |
//! | [`measure`] | Timing and peak memory |
//! | [`prover`] | The holder's native steps: unlock and sign, witness, prove |
//! | [`verifier`] | Verification of a presentation against the verifier's own values |
//!
//! The prover keeps no holder state: every call brings the credential material it needs. The
//! keys are built once from the circuits and kept, since they are deterministic.

pub mod circuit;
pub mod dates;
pub mod error;
pub mod handover;
pub mod keys;
pub mod mdoc;
pub mod measure;
pub mod presentation;
pub mod prover;
pub mod request;
pub mod verifier;
pub mod x509;

/// Lowercase hex of bytes.
pub fn hex(bytes: &[u8]) -> String {
  ::hex::encode(bytes)
}

/// `N` bytes from hex, or a description of what is wrong.
pub fn unhex<const N: usize>(what: &str, s: &str) -> Result<[u8; N], String> {
  let bytes = ::hex::decode(s).map_err(|e| format!("{what}: not hex ({e})"))?;
  bytes.try_into().map_err(|b: Vec<u8>| format!("{what}: {} bytes, expected {N}", b.len()))
}

/// base64url without padding (RFC 4648, clause 5), as OpenID4VP and JOSE write bytes.
pub fn b64url(bytes: &[u8]) -> String {
  use base64::Engine;
  base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Bytes from base64url without padding.
pub fn unb64url(what: &str, s: &str) -> Result<Vec<u8>, String> {
  use base64::Engine;
  base64::engine::general_purpose::URL_SAFE_NO_PAD
    .decode(s.trim())
    .map_err(|e| format!("{what}: not base64url without padding ({e})"))
}
