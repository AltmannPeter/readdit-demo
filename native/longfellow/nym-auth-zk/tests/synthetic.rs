//! Holders other than the rulebook vectors' (`tests/data/synthetic`, from `test-credentials/`):
//! TEST-ONLY credentials signed with the vectors' Document Signer key. B is 18 on 2026-10-28 (a
//! birthday edge), C was born on 29 February, D has no `psc` item (a 388-byte Sig_structure, the
//! same circuits). Each proves and verifies with a device signature made here, the pseudonym is
//! SHA-256(DST || secret_seed || 0^32 || verifier_input), and the age edges hold or fail exactly.

use nym_auth_zk::{AgeRange, Holder, Prover, Request, Session, Verifier};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use runtime_random::SecureRandomEngine;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn hex(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    let s = if s.len() % 2 == 1 { format!("0{s}") } else { s.to_string() };
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn json(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{}/tests/data/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap()
}

fn request(v: &Value, proof_time: &str, range: Option<&str>) -> Request {
    let k = &v["keys"]["document_signer"];
    Request {
        issuer_key: (hex(k["x"].as_str().unwrap()).try_into().unwrap(), hex(k["y"].as_str().unwrap()).try_into().unwrap()),
        proof_time: proof_time.into(),
        age_range: range.map(|r| AgeRange::parse(r).unwrap()),
        verifier_id: "x509_san_dns:verifier.example".into(),
        session: Session::Redirect {
            client_id: "x509_san_dns:verifier.example".into(),
            nonce: "synthetic-nonce".into(),
            jwk_thumbprint: None,
            response_uri: "https://verifier.example/response".into(),
        },
    }
}

#[test]
fn synthetic_holders() {
    let v = json("nym_auth_test_vectors.json");
    let prover = Prover::load().unwrap();
    let verifier = Verifier::load().unwrap();
    // (holder, proof_time, range, holds)
    let cases = [
        ("B", "2026-10-28T09:00:00Z", Some("18+"), true),
        ("B", "2026-10-27T23:59:59Z", Some("18+"), false),
        ("B", "2026-10-27T23:59:59Z", Some("13-17"), true),
        ("C", "2026-10-28T09:00:00Z", Some("13-17"), true),
        ("C", "2026-10-28T09:00:00Z", Some("15+"), false),
        ("D", "2026-10-28T09:00:00Z", Some("18+"), true),
        ("D", "2026-10-28T09:00:00Z", None, true),
    ];
    for (h, t, range, holds) in cases {
        let d = json(&format!("synthetic/holder{h}.json"));
        let cred = hex(d["issuer_signed"].as_str().unwrap());
        let mut dk = [0u8; 32];
        let key = hex(d["device_d"].as_str().unwrap());
        dk[32 - key.len()..].copy_from_slice(&key);
        let holder = Holder {
            credential: &cred,
            secret_seed: hex(d["secret_seed"].as_str().unwrap()).try_into().unwrap(),
            birth_date: d["birth_date"].as_str().unwrap().as_bytes().try_into().unwrap(),
        };
        let r = request(&v, t, range);
        let sig: Signature = SigningKey::from_bytes(&dk.into()).unwrap().sign(&Prover::device_signed_bytes(&r));
        let sig: [u8; 64] = sig.to_bytes().into();
        let got = prover.prove(&r, &holder, &sig, &mut SecureRandomEngine::new());
        assert_eq!(got.is_ok(), holds, "holder {h} at {t} range {range:?}: {got:?}");
        if let Ok(p) = got {
            verifier.verify(&r, &p).unwrap();
            let vi = Sha256::digest(b"x509_san_dns:verifier.example");
            let mut m = b"nym_auth/v1/known-offender-matching-ssc".to_vec();
            m.extend_from_slice(&holder.secret_seed);
            m.extend_from_slice(&[0u8; 32]);
            m.extend_from_slice(&vi);
            assert_eq!(p.pseudonym.to_vec(), Sha256::digest(&m).to_vec(), "holder {h}");
        }
    }
}
