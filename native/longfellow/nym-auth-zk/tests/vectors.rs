//! End to end on the nym_auth rulebook's test vectors (tests/data): honest presentations prove and
//! verify for both session channels and both credential variants, the pseudonym is the vectors'
//! known-offender-matching-ssc pseudonym, the age cases hold or fail as the vectors say, and
//! tampered or mismatched presentations are refused.

use nym_auth_zk::{AgeRange, Error, Holder, Presentation, Prover, Request, Session, Verifier};
use runtime_random::SecureRandomEngine;
use serde_json::Value;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex(s).try_into().unwrap()
}

struct Vectors {
    v: Value,
}

impl Vectors {
    fn load(name: &str) -> Vectors {
        let p = format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
        Vectors { v: serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap() }
    }
    fn s(&self, path: &[&str]) -> String {
        let mut x = &self.v;
        for k in path {
            x = &x[*k];
        }
        x.as_str().unwrap().to_string()
    }
    fn session(&self, ch: &str) -> Session {
        let i = &self.v["sessions"][ch]["inputs"];
        let t = i["jwk_thumbprint"].as_str().map(arr::<32>);
        match ch {
            "redirect" => Session::Redirect {
                client_id: i["client_id"].as_str().unwrap().into(),
                nonce: i["nonce"].as_str().unwrap().into(),
                jwk_thumbprint: t,
                response_uri: i["response_uri"].as_str().unwrap().into(),
            },
            _ => Session::DcApi {
                origin: i["origin"].as_str().unwrap().into(),
                nonce: i["nonce"].as_str().unwrap().into(),
                jwk_thumbprint: t,
            },
        }
    }
    fn request(&self, ch: &str, range: Option<&str>) -> Request {
        Request {
            issuer_key: (
                arr(&self.s(&["keys", "document_signer", "x"])),
                arr(&self.s(&["keys", "document_signer", "y"])),
            ),
            proof_time: self.s(&["expected", "age_check", "proof_time"]),
            age_range: range.map(|r| AgeRange::parse(r).unwrap()),
            verifier_id: self.s(&["expected", "pseudonym_inputs", "verifier_id"]),
            session: self.session(ch),
        }
    }
    fn credential(&self) -> Vec<u8> {
        hex(&self.s(&["issuer_signed_cbor"]))
    }
    fn holder<'a>(&self, cred: &'a [u8]) -> Holder<'a> {
        Holder {
            credential: cred,
            secret_seed: arr(&self.s(&["holder_openings", "secret_seed"])),
            birth_date: self.s(&["holder_openings", "birth_date"]).as_bytes().try_into().unwrap(),
        }
    }
    fn device_sig(&self, ch: &str) -> [u8; 64] {
        arr(&self.s(&["sessions", ch, "device_signature_r_s"]))
    }
}

#[test]
fn device_signed_bytes_are_the_vectors() {
    for f in ["nym_auth_test_vectors.json", "nym_auth_test_vectors_zero_psc.json"] {
        let v = Vectors::load(f);
        for ch in ["redirect", "dcapi"] {
            let r = v.request(ch, None);
            assert_eq!(
                Prover::device_signed_bytes(&r),
                hex(&v.s(&["sessions", ch, "device_sig_structure"])),
                "{f} {ch}"
            );
        }
    }
}

#[test]
fn the_rulebook_age_cases() {
    let v = Vectors::load("nym_auth_test_vectors.json");
    let prover = Prover::load().unwrap();
    let verifier = Verifier::load().unwrap();
    let cred = v.credential();
    let holder = v.holder(&cred);
    let expected = arr::<32>(&v.s(&["expected", "pseudonyms_sha256", "known-offender-matching-ssc"]));
    let cases = v.v["expected"]["age_check"]["cases"].as_array().unwrap().clone();
    for c in cases {
        let range = c["range"].as_str().unwrap();
        let holds = c["holds"].as_bool().unwrap();
        let r = v.request("dcapi", Some(range));
        let res = prover.prove(&r, &holder, &v.device_sig("dcapi"), &mut SecureRandomEngine::new());
        if holds {
            let p = res.unwrap_or_else(|e| panic!("{range}: {e}"));
            assert_eq!(p.pseudonym, expected);
            verifier.verify(&r, &p).unwrap_or_else(|e| panic!("{range}: {e}"));
        } else {
            assert_eq!(res.err(), Some(Error::Holder("birth_date is outside the age range")), "{range}");
        }
    }
}

#[test]
fn both_channels_both_variants_and_refusals() {
    let prover = Prover::load().unwrap();
    let verifier = Verifier::load().unwrap();
    for f in ["nym_auth_test_vectors.json", "nym_auth_test_vectors_zero_psc.json"] {
        let v = Vectors::load(f);
        let cred = v.credential();
        let holder = v.holder(&cred);
        for ch in ["redirect", "dcapi"] {
            let r = v.request(ch, Some("13-17"));
            let p = prover.prove(&r, &holder, &v.device_sig(ch), &mut SecureRandomEngine::new()).unwrap();
            verifier.verify(&r, &p).unwrap();
            println!("{f} {ch}: proof {} bytes", p.proof.len());

            // A second presentation shares no commitment.
            let p2 = prover.prove(&r, &holder, &v.device_sig(ch), &mut SecureRandomEngine::new()).unwrap();
            assert_ne!(p.proof[..96], p2.proof[..96]);
            assert_eq!(p.pseudonym, p2.pseudonym);

            // Tampered proof bytes, a wrong pseudonym.
            for at in [0usize, 100, p.proof.len() / 2, p.proof.len() - 1] {
                let mut t = p.clone();
                t.proof[at] ^= 1;
                assert!(verifier.verify(&r, &t).is_err(), "{f} {ch} byte {at}");
            }
            let mut t = p.clone();
            t.pseudonym[0] ^= 1;
            assert!(verifier.verify(&r, &t).is_err());

            // Another verifier_id, another range, another time, another issuer key, the other
            // session: the presentation does not verify.
            let mut o = r.clone();
            o.verifier_id.push('x');
            assert!(verifier.verify(&o, &p).is_err());
            let mut o = r.clone();
            o.age_range = Some(AgeRange::parse("12-16").unwrap());
            assert!(verifier.verify(&o, &p).is_err());
            let mut o = r.clone();
            o.proof_time = "2026-10-27T12:00:01Z".into();
            assert!(verifier.verify(&o, &p).is_err());
            let mut o = r.clone();
            o.issuer_key.0[31] ^= 1;
            assert!(verifier.verify(&o, &p).is_err());
            let other = if ch == "dcapi" { "redirect" } else { "dcapi" };
            let o = v.request(other, Some("13-17"));
            assert!(verifier.verify(&o, &p).is_err());
        }
    }
}

#[test]
fn the_prover_refuses_what_the_statement_does_not_hold() {
    let v = Vectors::load("nym_auth_test_vectors.json");
    let prover = Prover::load().unwrap();
    let cred = v.credential();
    let r = v.request("dcapi", Some("13-17"));
    let sig = v.device_sig("dcapi");
    let rng = &mut SecureRandomEngine::new();
    // Another birth date, or another seed: the opening does not open bsc.
    let mut h = v.holder(&cred);
    h.birth_date = *b"2010-05-18";
    assert_eq!(prover.prove(&r, &h, &sig, rng).err(), Some(Error::Holder("secret_seed and birth_date do not open bsc")));
    let mut h = v.holder(&cred);
    h.secret_seed[0] ^= 1;
    assert_eq!(prover.prove(&r, &h, &sig, rng).err(), Some(Error::Holder("secret_seed and birth_date do not open bsc")));
    // A wrong device signature, the other session's.
    let h = v.holder(&cred);
    assert_eq!(
        prover.prove(&r, &h, &v.device_sig("redirect"), rng).err(),
        Some(Error::Holder("the device signature does not verify under the credential's device key"))
    );
    // Outside the validity: before validFrom, after validUntil.
    for t in ["2026-10-26T23:59:59Z", "2027-10-27T00:00:01Z"] {
        let mut o = r.clone();
        o.proof_time = t.into();
        assert_eq!(prover.prove(&o, &h, &sig, rng).err(), Some(Error::Holder("the credential is not valid at proof_time")), "{t}");
    }
    // At the bounds, inclusive: validFrom and validUntil themselves.
    let verifier = Verifier::load().unwrap();
    for t in ["2026-10-27T00:00:00Z", "2027-10-27T00:00:00Z"] {
        let mut o = r.clone();
        o.proof_time = t.into();
        o.age_range = None;
        let p = prover.prove(&o, &h, &sig, rng).unwrap_or_else(|e| panic!("{t}: {e}"));
        verifier.verify(&o, &p).unwrap();
    }
    // Another issuer key.
    let mut o = r.clone();
    o.issuer_key.1[0] ^= 1;
    assert!(prover.prove(&o, &h, &sig, rng).is_err());
    let _ = Presentation { pseudonym: [0; 32], proof: vec![] };
}
