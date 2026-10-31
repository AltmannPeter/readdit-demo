//! Holders other than the rulebook vectors' (`tests/data/decoy_synthetic_holders.json`): TEST-ONLY
//! credentials in the decoy-digest layout signed with the vectors' Document Signer key, each at an
//! edge. B was born 2008-10-28 and its credential is valid for the one second 2026-10-27T12:00:00Z
//! (validFrom == validUntil); C was born on 29 February 2000; D was born 2013-10-27, has a zero
//! `psc`, and its credential is valid from 2026-10-26T23:59:59Z to 2026-10-27T12:00:00Z. Each
//! proves and verifies with a device signature made here, the pseudonym is
//! SHA-256(DST || secret_seed || 0^32 || verifier_input), and the edges hold or fail exactly.

use nym_auth_zk_decoy::{AgeRange, Error, Holder, Prover, Request, Session, Verifier};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use runtime_random::SecureRandomEngine;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn hex(s: &str) -> Vec<u8> {
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
fn synthetic_holders_at_their_edges() {
    let v = json("decoy_test_vectors.json");
    let s = json("decoy_synthetic_holders.json");
    let dk: [u8; 32] = hex(v["keys"]["device"]["d"].as_str().unwrap()).try_into().unwrap();
    let prover = Prover::load().unwrap();
    let verifier = Verifier::load().unwrap();
    let range_refusal = Some(Error::Holder("birth_date is outside the age range"));
    let validity_refusal = Some(Error::Holder("the credential is not valid at proof_time"));
    // (holder, proof_time, range, the refusal or None)
    let cases = [
        ("B", "2026-10-27T12:00:00Z", Some("13-17"), None), // birth == E, now == validFrom == validUntil
        ("B", "2026-10-27T12:00:00Z", Some("18+"), range_refusal.clone()),
        ("B", "2026-10-27T12:00:01Z", Some("13-17"), validity_refusal.clone()),
        ("B", "2026-10-27T11:59:59Z", Some("13-17"), validity_refusal.clone()),
        ("C", "2026-10-28T09:00:00Z", Some("18+"), None),
        ("C", "2028-02-28T09:00:00Z", Some("27-"), None),
        ("C", "2028-02-29T09:00:00Z", Some("27-"), range_refusal.clone()),
        ("D", "2026-10-27T12:00:00Z", Some("13-17"), None), // birth == C, now == validUntil
        ("D", "2026-10-26T23:59:59Z", None, None),          // now == validFrom
        ("D", "2026-10-27T12:00:00Z", Some("14+"), range_refusal.clone()),
        ("D", "2026-10-26T23:59:58Z", None, validity_refusal.clone()),
    ];
    for (h, t, range, refusal) in cases {
        let d = &s["holders"][h];
        let cred = hex(d["issuer_signed"].as_str().unwrap());
        let holder = Holder {
            credential: &cred,
            secret_seed: hex(d["secret_seed"].as_str().unwrap()).try_into().unwrap(),
            birth_date: d["birth_date"].as_str().unwrap().as_bytes().try_into().unwrap(),
        };
        let r = request(&v, t, range);
        let sig: Signature = SigningKey::from_bytes(&dk.into()).unwrap().sign(&Prover::device_signed_bytes(&r));
        let sig: [u8; 64] = sig.to_bytes().into();
        let got = prover.prove(&r, &holder, &sig, &mut SecureRandomEngine::new());
        assert_eq!(got.as_ref().err(), refusal.as_ref(), "holder {h} at {t} range {range:?}");
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
