//! The nym_auth attestation in its `bbs_cd` encoding (rulebook v0.4): a BBS credential with
//! committed disclosures (ETSI draft v0.7, `bbs-cd-plugins`), presented over OpenID4VP as a
//! `zkp_req` `ZkpPresentation`.
//!
//! - [`profile`]: the credential schema and the mapping from an OpenID4VP Request Object and its
//!   handover to the BBS request both sides compute (`docs/bbs_cd.md`).
//! - [`presentation`]: `ZkpPresentation` in CBOR.
//! - [`credential`]: the credential as the wallet stores it (JSON).
//! - [`prover`] and [`verifier`]: the holder's presentation and its verification.
//!
//! The vendored crates are research code: not constant-time, not audited.
#![forbid(unsafe_code)]

pub mod credential;
pub mod dates;
pub mod error;
pub mod measure;
pub mod presentation;
pub mod profile;
pub mod prover;
pub mod verifier;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub fn hex(b: &[u8]) -> String {
    hex::encode(b)
}

pub fn b64url(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

pub fn unb64url(what: &str, s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).map_err(|e| format!("{what} is not base64url: {e}"))
}
