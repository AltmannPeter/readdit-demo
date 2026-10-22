//! Prover and verifier of the nym_auth statement (age range and the `pseudonym` function with `prf` `sha-256`,
//! configuration `known-offender-matching-ssc`) with Longfellow, as the Community demo runs them.
//!
//! The circuits are the nym-auth-circuits archive's LFC2 pair for mdoc (`circuits/mdoc`), run on
//! Google's longfellow-zk Rust runtime, vendored unchanged. The witness follows SPEC.md L3 to L5
//! and the protocol L6, as the archive's reference program (`longfellow/reference`) implements
//! them. This crate adds what an OpenID4VP presentation needs around them:
//!
//! | Module | Role |
//! | --- | --- |
//! | [`circuit`] | The registry values: circuit id, proof system, public inputs |
//! | [`handover`] | SessionTranscript `[null, null, OpenID4VPHandover]` (OpenID4VP 1.0, B.2.6.1) and the device challenge |
//! | [`request`] | The verifier's values from the signed Request Object and the handover (rulebook, "Verification") |
//! | [`dates`] | Full-dates, date-times and the clock |
//! | [`cbor`] | A CBOR reader that keeps each item's encoding, and the few items both sides write |
//! | [`mdoc`] | The holder's IssuerSigned taken apart |
//! | [`x509`] | The Document Signer certificate of `issuer_key_set` |
//! | [`presentation`] | `ZkpPresentation` in CBOR (rulebook, "Presentation encoding") |
//! | [`sha`] | SHA-256 with the block faces the hash circuit checks (L4.1) |
//! | [`witness`] | The two input vectors (L3 to L5) and the MAC (L6) |
//! | [`zk`] | The circuits loaded into Google's runtime; prove and verify (L6.2, L6.3) |
//! | [`measure`] | Timing and peak memory |
//! | [`prover`] | The holder's native steps: unlock and sign, witness, prove |
//! | [`verifier`] | Verification of a presentation against the verifier's own values |
//!
//! The SessionTranscript differs from the archive's fixtures, which use the Digital Credentials
//! API handover (`OpenID4VPDCAPIHandover`). Community's wallet is invoked by a QR code, so B.2.6.1
//! applies. The circuits do not see the transcript: they take e2, its digest under
//! DeviceAuthentication, as a public input, and the transcript seeds Fiat–Shamir on both sides.
//!
//! The prover keeps no holder state: every call brings the credential material it needs.

pub mod cbor;
pub mod circuit;
pub mod dates;
pub mod error;
pub mod handover;
pub mod mdoc;
pub mod measure;
pub mod presentation;
pub mod prover;
pub mod request;
pub mod sha;
pub mod verifier;
pub mod witness;
pub mod x509;
pub mod zk;

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

/// SHA-256.
pub fn sha256(m: &[u8]) -> [u8; 32] {
  use sha2::Digest;
  sha2::Sha256::digest(m).into()
}
