//! P2: proofs made with `AesCtrRng` verify (with the feature `google-verifier`, under Google's
//! verifier), changed proofs do not, and two proofs of the same statement differ (a new key per
//! engine).

#![cfg(feature = "aes-rng")]

use nym_auth_zk_decoy_opt::{AesCtrRng, AgeRange, Holder, Prover, Request, Session, Verifier};
use serde_json::Value;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

#[test]
fn aes_ctr_proofs_verify_and_differ() {
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
    let sig: [u8; 64] = hex(&s(&["sessions", "redirect", "device_signature_r_s"])).try_into().unwrap();
    let prover = Prover::load().unwrap();
    let verifier = Verifier::load().unwrap();
    let prove = || {
        let mut rng = AesCtrRng::new();
        let pre = prover.prebuild(&r, &holder, &mut rng).unwrap();
        prover.prove_prebuilt(pre, &sig, &mut rng).unwrap()
    };
    let (a, b) = (prove(), prove());
    verifier.verify(&r, &a).unwrap();
    verifier.verify(&r, &b).unwrap();
    assert_eq!(a.pseudonym, b.pseudonym);
    assert_ne!(a.proof, b.proof, "a new key per engine");
    let n = a.proof.len();
    for j in 0..60 {
        let mut q = a.clone();
        q.proof[(j * 4799 + 13) % n] ^= 1 << (j % 8);
        assert!(verifier.verify(&r, &q).is_err(), "flip {j}");
    }
    let mut q = a.clone();
    q.proof.pop();
    assert!(verifier.verify(&r, &q).is_err());
}
