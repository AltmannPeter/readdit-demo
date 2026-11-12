//! P1: the hash circuit's Ligero table keeps its subfield rows at 2 bytes an entry. Its 103 rows
//! of 2,546 entries took 4,195,808 bytes as full elements; 90 of them lie in the subfield.

#![cfg(not(feature = "reference"))]

use nym_auth_zk_decoy_opt::{AgeRange, Holder, Prover, Request, Session};
use runtime_random::SecureRandomEngine;
use serde_json::Value;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

#[test]
fn the_hash_table_is_packed() {
    let p = format!("{}/tests/data/decoy_test_vectors.json", env!("CARGO_MANIFEST_DIR"));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let s = |path: &[&str]| path.iter().fold(&v, |x, k| &x[*k]).as_str().unwrap().to_string();
    let i = &v["sessions"]["redirect"]["inputs"];
    let r = Request {
        issuer_key: (hex(&s(&["keys", "document_signer", "x"])).try_into().unwrap(), hex(&s(&["keys", "document_signer", "y"])).try_into().unwrap()),
        proof_time: s(&["expected", "age_check", "proof_time"]),
        age_range: Some(AgeRange::parse("13-17").unwrap()),
        verifier_id: s(&["expected", "pseudonym_inputs", "verifier_id"]),
        session: Session::Redirect {
            client_id: i["client_id"].as_str().unwrap().into(),
            nonce: i["nonce"].as_str().unwrap().into(),
            jwk_thumbprint: i["jwk_thumbprint"].as_str().map(|t| hex(t).try_into().unwrap()),
            response_uri: i["response_uri"].as_str().unwrap().into(),
        },
    };
    let cred = hex(&s(&["issuer_signed_cbor"]));
    let holder = Holder {
        credential: &cred,
        secret_seed: hex(&s(&["holder_openings", "secret_seed"])).try_into().unwrap(),
        birth_date: s(&["holder_openings", "birth_date"]).as_bytes().try_into().unwrap(),
    };
    let pre = Prover::load().unwrap().prebuild(&r, &holder, &mut SecureRandomEngine::new()).unwrap();
    let held = pre.table_bytes();
    eprintln!("hash table: {held} bytes");
    assert_eq!(held, 13 * 2546 * 16 + 90 * 2546 * 2, "13 full rows and 90 packed rows");
}
