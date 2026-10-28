//! Times a presentation on the rulebook's test vectors: circuit load, prove, verify, proof size.
//!
//!   cargo run --release --example bench [REPS]
//!
//! Build with `RUSTFLAGS="-C target-cpu=native"` on x86-64 for the GF(2^128) carry-less multiply.

use nym_auth_zk::{AgeRange, Holder, Prover, Request, Session, Verifier};
use runtime_random::SecureRandomEngine;
use std::time::Instant;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn main() {
    let reps: usize = std::env::args().nth(1).map_or(5, |s| s.parse().unwrap());
    let p = format!("{}/tests/data/nym_auth_test_vectors.json", env!("CARGO_MANIFEST_DIR"));
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let s = |path: &[&str]| -> String {
        let mut x = &v;
        for k in path {
            x = &x[*k];
        }
        x.as_str().unwrap().to_string()
    };
    let i = &v["sessions"]["dcapi"]["inputs"];
    let request = Request {
        issuer_key: (
            hex(&s(&["keys", "document_signer", "x"])).try_into().unwrap(),
            hex(&s(&["keys", "document_signer", "y"])).try_into().unwrap(),
        ),
        proof_time: s(&["expected", "age_check", "proof_time"]),
        age_range: Some(AgeRange::parse("13-17").unwrap()),
        verifier_id: s(&["expected", "pseudonym_inputs", "verifier_id"]),
        session: Session::DcApi {
            origin: i["origin"].as_str().unwrap().into(),
            nonce: i["nonce"].as_str().unwrap().into(),
            jwk_thumbprint: Some(hex(i["jwk_thumbprint"].as_str().unwrap()).try_into().unwrap()),
        },
    };
    let cred = hex(&s(&["issuer_signed_cbor"]));
    let holder = Holder {
        credential: &cred,
        secret_seed: hex(&s(&["holder_openings", "secret_seed"])).try_into().unwrap(),
        birth_date: s(&["holder_openings", "birth_date"]).as_bytes().try_into().unwrap(),
    };
    let sig: [u8; 64] = hex(&s(&["sessions", "dcapi", "device_signature_r_s"])).try_into().unwrap();

    let t = Instant::now();
    let prover = Prover::load().unwrap();
    let load_p = t.elapsed();
    let t = Instant::now();
    let verifier = Verifier::load().unwrap();
    let load_v = t.elapsed();
    println!("load: prover {load_p:.1?}, verifier {load_v:.1?}");
    for _ in 0..reps {
        let rng = &mut SecureRandomEngine::new();
        let t = Instant::now();
        let pre = prover.prebuild(&request, &holder, rng).unwrap();
        let t1 = t.elapsed();
        let t = Instant::now();
        let pres = prover.prove_prebuilt(pre, &sig, rng).unwrap();
        let t2 = t.elapsed();
        let tp = t1 + t2;
        let t = Instant::now();
        verifier.verify(&request, &pres).unwrap();
        let tv = t.elapsed();
        println!("prove {tp:.1?} (prebuild {t1:.1?} + after signature {t2:.1?})  verify {tv:.1?}  proof {} bytes (+32 pseudonym)", pres.proof.len());
    }
}
