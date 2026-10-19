//! Independent Rust reference for ETSI BBS committed disclosures v0.7.
//!
//! This crate is not constant-time and is not for production use.
//! Profile signatures, commitments and proofs follow the specification's procedures.
#![forbid(unsafe_code)]
#![allow(non_snake_case)]

/// Spec 1.3–1.4: input, outcome, and protocol state types.
pub mod types;
pub use types::{BbsError, BbsResult, INVALID};

/// Parameters and ciphersuite identifiers from spec Sections 3.1–3.2.
pub mod params;

/// Cryptographic primitives and point handling from spec Sections 1.5 and 4.2.4.
pub mod primitives;

/// Notation helpers and validation predicates from spec Sections 1.4 and 4.1.4.
pub mod helpers;

/// Generator, message mapping, commitment, and serialization utilities from spec Sections 4.1–4.2.
pub mod utils;

/// BBS core signing and proof procedures from spec Sections 3.6–3.7.
pub mod core;
mod proof_protocol;

/// Key, signing, proof, and commitment interface procedures from spec Sections 3.4–3.5 and 4.1.3.
pub mod interface;

/// Fixture-only injectable randomness support for spec Section 4.2.1.
pub mod mock_rng;

#[cfg(test)]
mod m1_contracts;

#[cfg(test)]
mod bbs_vectors;

#[cfg(test)]
mod profile_vectors;

#[cfg(test)]
mod exceptional_hash_tests;

#[cfg(test)]
mod optimization_tests;
