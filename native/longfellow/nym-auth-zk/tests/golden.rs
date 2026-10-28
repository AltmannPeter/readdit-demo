//! The golden presentations (`tests/golden/*.json`, written once by `examples/golden.rs`) verify
//! with their requests, and fail with any changed request value. Any port of the verifier, or a
//! wallet's own build of the prover, can be checked against the same files.

use nym_auth_zk::{AgeRange, Presentation, Prover, Request, Session, Verifier};
use serde_json::Value;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex(s).try_into().unwrap()
}

/// A golden file's request and presentation.
pub fn read(g: &Value) -> (Request, Presentation) {
    let r = &g["request"];
    let st = |v: &Value| v.as_str().unwrap().to_string();
    let se = &r["session"];
    let t = se["jwk_thumbprint"].as_str().map(arr::<32>);
    let session = match se["type"].as_str().unwrap() {
        "redirect" => Session::Redirect {
            client_id: st(&se["client_id"]),
            nonce: st(&se["nonce"]),
            jwk_thumbprint: t,
            response_uri: st(&se["response_uri"]),
        },
        _ => Session::DcApi { origin: st(&se["origin"]), nonce: st(&se["nonce"]), jwk_thumbprint: t },
    };
    let request = Request {
        issuer_key: (arr(&st(&r["issuer_key"]["x"])), arr(&st(&r["issuer_key"]["y"]))),
        proof_time: st(&r["proof_time"]),
        age_range: r["age_range"].as_str().map(|a| AgeRange::parse(a).unwrap()),
        verifier_id: st(&r["verifier_id"]),
        session,
    };
    let p = &g["presentation"];
    (request, Presentation { pseudonym: arr(&st(&p["pseudonym"])), proof: hex(&st(&p["proof"])) })
}

#[test]
fn golden_presentations_verify() {
    let dir = format!("{}/tests/golden", env!("CARGO_MANIFEST_DIR"));
    let verifier = Verifier::load().unwrap();
    let mut n = 0;
    for e in std::fs::read_dir(&dir).unwrap() {
        let path = e.unwrap().path();
        let g: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let (request, p) = read(&g);
        assert_eq!(Prover::device_signed_bytes(&request), hex(g["device_signed_bytes"].as_str().unwrap()));
        verifier.verify(&request, &p).unwrap_or_else(|e| panic!("{}: {e:?}", path.display()));

        let mut r = request.clone();
        r.verifier_id.push('x');
        assert!(verifier.verify(&r, &p).is_err());
        let mut r = request.clone();
        r.proof_time = "2026-10-27T12:00:01Z".into();
        assert!(verifier.verify(&r, &p).is_err());
        let mut r = request.clone();
        r.age_range = Some(AgeRange::parse("0+").unwrap());
        assert!(verifier.verify(&r, &p).is_err());
        let mut q = p.clone();
        q.pseudonym[0] ^= 1;
        assert!(verifier.verify(&request, &q).is_err());
        n += 1;
    }
    assert_eq!(n, 3);
}
