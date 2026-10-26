//! The registry values of the circuits this crate proves and verifies. `shared/registry/circuits.ts`
//! holds the same entry; the site offers the circuits only when the names and the order of the
//! public inputs below, and the hash of the loaded `circuits.zst`, equal the registry's.

/// The approved circuit's identifier: the LFC2 pair (hash circuit, signature circuit) for mdoc.
pub const CIRCUIT_ID: &str = "urn:circuits:longfellow:nym_auth:v1";

/// The proof system: Google longfellow-zk `61a8a73`, Ligero over sumcheck (libzk), Rust runtime.
pub const PROOF_SYSTEM: &str = "longfellow-libzk-v1";

/// The runtime, for the services' `info`.
pub const RUNTIME: &str = "google/longfellow-zk 61a8a73 (Rust runtime)";

/// The attestation's document type and namespace (rulebook, "Document Type and Namespace").
pub const DOC_TYPE: &str = "eu.europa.ec.eudi.nym_auth.1";

/// The data elements the hash circuit reads.
pub const BIRTH_DATE: &str = "birth_date";
pub const SSC: &str = "ssc";

/// The pseudonym's domain separation tag (SPEC.md §1, row 7).
pub const DST: &[u8] = b"nym_auth/v1/known-offender-matching-ssc";

/// The public inputs, grouped by the input they encode, with the elements each takes in the hash
/// circuit (GF(2^128)) and in the signature circuit (P-256) (SPEC.md L3). Each circuit's
/// constant 1 in slot 0 is left out. Hash: 585 + 1 = 586 public slots; signature: 1154 + 1 = 1155.
pub const PUBLIC_INPUTS: [(&str, usize, usize); 9] = [
  ("proof_time", 160, 0),
  ("age_check.ge", 80, 0),
  ("age_check.le", 80, 0),
  ("pseudonym.verifier_input", 256, 0),
  ("mac.tags", 6, 768),
  ("mac.a_v", 1, 128),
  ("results.nym", 2, 0),
  ("issuer_key_set", 0, 2),
  ("session_transcript", 0, 256),
];

/// The name of the artifact the registry pins.
pub const ARTIFACT: &str = "circuits.zst";

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn public_inputs_fill_the_public_slots() {
    let hash: usize = PUBLIC_INPUTS.iter().map(|p| p.1).sum();
    let sig: usize = PUBLIC_INPUTS.iter().map(|p| p.2).sum();
    assert_eq!((hash + 1, sig + 1), (586, 1155));
  }
}
