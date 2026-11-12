//! Writes the golden presentations (`tests/golden/*.json`): fixed requests on the rulebook's test
//! vectors, with the vectors' own device signatures, proved once. A proof is randomized, so a
//! re-run writes other proof bytes; the shipped files are the reference that every verifier
//! (Rust, a wallet's, the demo site's) must accept, checked by `tests/golden.rs`.
//!
//!   cargo run --release --example golden

use nym_auth_zk::{AgeRange, Holder, Prover, Request, Session, Verifier};
use runtime_random::SecureRandomEngine;
use serde_json::{json, Value};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex(s).try_into().unwrap()
}
fn enc(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let dir = format!("{}/tests", env!("CARGO_MANIFEST_DIR"));
    std::fs::create_dir_all(format!("{dir}/golden")).unwrap();
    let prover = Prover::load().unwrap();
    let verifier = Verifier::load().unwrap();
    let cases = [
        ("redirect_13-17", "nym_auth_test_vectors.json", "redirect", Some("13-17")),
        ("redirect_16-_zero_psc", "nym_auth_test_vectors_zero_psc.json", "redirect", Some("16-")),
        ("dcapi_no-range_zero_psc", "nym_auth_test_vectors_zero_psc.json", "dcapi", None),
    ];
    for (name, file, ch, range) in cases {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(format!("{dir}/data/{file}")).unwrap()).unwrap();
        let s = |p: &[&str]| p.iter().fold(&v, |x, k| &x[*k]).as_str().unwrap().to_string();
        let i = &v["sessions"][ch]["inputs"];
        let t = i["jwk_thumbprint"].as_str();
        let (session, session_json) = match ch {
            "redirect" => (
                Session::Redirect {
                    client_id: i["client_id"].as_str().unwrap().into(),
                    nonce: i["nonce"].as_str().unwrap().into(),
                    jwk_thumbprint: t.map(arr::<32>),
                    response_uri: i["response_uri"].as_str().unwrap().into(),
                },
                json!({ "type": "redirect", "client_id": i["client_id"], "nonce": i["nonce"],
                        "jwk_thumbprint": t, "response_uri": i["response_uri"] }),
            ),
            _ => (
                Session::DcApi {
                    origin: i["origin"].as_str().unwrap().into(),
                    nonce: i["nonce"].as_str().unwrap().into(),
                    jwk_thumbprint: t.map(arr::<32>),
                },
                json!({ "type": "dcapi", "origin": i["origin"], "nonce": i["nonce"], "jwk_thumbprint": t }),
            ),
        };
        let request = Request {
            issuer_key: (arr(&s(&["keys", "document_signer", "x"])), arr(&s(&["keys", "document_signer", "y"]))),
            proof_time: s(&["expected", "age_check", "proof_time"]),
            age_range: range.map(|r| AgeRange::parse(r).unwrap()),
            verifier_id: s(&["expected", "pseudonym_inputs", "verifier_id"]),
            session,
        };
        let cred = hex(&s(&["issuer_signed_cbor"]));
        let holder = Holder {
            credential: &cred,
            secret_seed: arr(&s(&["holder_openings", "secret_seed"])),
            birth_date: s(&["holder_openings", "birth_date"]).as_bytes().try_into().unwrap(),
        };
        let sig = arr::<64>(&s(&["sessions", ch, "device_signature_r_s"]));
        let p = prover.prove(&request, &holder, &sig, &mut SecureRandomEngine::new()).unwrap();
        verifier.verify(&request, &p).unwrap();
        let out = json!({
            "comment": "TEST ONLY. A presentation of nym-auth-zk on the rulebook's test vectors; every verifier must accept it with exactly this request.",
            "vectors": file,
            "request": {
                "issuer_key": { "x": s(&["keys", "document_signer", "x"]), "y": s(&["keys", "document_signer", "y"]) },
                "issuer_cert_der": s(&["keys", "document_signer", "cert_der"]),
                "proof_time": request.proof_time,
                "age_range": range,
                "verifier_id": request.verifier_id,
                "session": session_json,
            },
            "device_signed_bytes": enc(&Prover::device_signed_bytes(&request)),
            "device_signature_r_s": enc(&sig),
            "presentation": { "pseudonym": enc(&p.pseudonym), "proof": enc(&p.proof) },
            "proof_bytes": p.proof.len(),
        });
        std::fs::write(format!("{dir}/golden/{name}.json"), serde_json::to_string_pretty(&out).unwrap()).unwrap();
        println!("{name}: {} proof bytes", p.proof.len());
    }
}
