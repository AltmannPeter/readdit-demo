//! The registry values of the circuit this crate proves and verifies. `shared/registry/circuits.ts`
//! holds the same entry; the site offers the circuit only when the names and the order of the
//! public inputs below, and the hash of the loaded shapes, equal the registry's.

use vega_age::table::{FULL_MDOC, Layout};

/// The approved circuit's identifier: `urn:circuits:sha256:` and the SHA-256 of the archive as
/// shipped, `circuits/mdoc/shapes.zst`.
pub const CIRCUIT_ID: &str = "urn:circuits:sha256:b457ba5382eb7604ef035e790f2cb24f0cd5fdcd065f383ff1c2c49fab1bb4df";

/// The proof system: Microsoft vega-prover `c0ee259`, `VegaMcZkSNARK` over `T256HyraxEngine`.
pub const PROOF_SYSTEM: &str = "vega-v1";

/// The attestation's document type and namespace (rulebook, "Document Type and Namespace").
pub const DOC_TYPE: &str = "eu.europa.ec.eudi.nym_auth.1";

/// The data elements the circuit reads.
pub const BIRTH_DATE: &str = "birth_date";
pub const SSC: &str = "ssc";

/// The table's layout of the full statement on an mdoc (32 step instances and the core).
pub const LAYOUT: Layout = FULL_MDOC;

/// The core circuit's public values in order, grouped by the input they encode, with the number
/// of field elements each takes (SPEC.md V3.2). 18 values.
pub const PUBLIC_INPUTS: [(&str, usize); 9] = [
  ("issuer_key_set", 2),
  ("age_check.ge", 1),
  ("age_check.le", 1),
  ("proof_time", 1),
  ("session_transcript", 2),
  ("doctype", 3),
  ("birth_date.identifier", 3),
  ("pseudonym.verifier_input", 3),
  ("results.nym", 2),
];

/// The number of core public values.
pub const PUBLIC_VALUES: usize = {
  let mut n = 0;
  let mut i = 0;
  while i < PUBLIC_INPUTS.len() {
    n += PUBLIC_INPUTS[i].1;
    i += 1;
  }
  n
};

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

#[cfg(test)]
mod tests {
  #[test]
  fn circuit_id_is_the_archive_hash() {
    let file = std::fs::read(format!("{}/../circuits/mdoc/shapes.zst", env!("CARGO_MANIFEST_DIR"))).unwrap();
    assert_eq!(super::CIRCUIT_ID, format!("urn:circuits:sha256:{}", crate::hex(&vega_age::table::sha256(&file))));
  }
}
