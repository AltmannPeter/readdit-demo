//! Prints, for fixed test requests and a fixed deterministic random engine (Google's
//! `DeterministicRng`, for tests only), the SHA-256 of each presentation's proof and the verifier's
//! verdict on it and on tampered copies. The output must be the same for every build and thread
//! count: run it with `RAYON_NUM_THREADS` = 1, 2, 4, 8, with `--no-default-features` (no threads)
//! and with `--features reference` (Google's own `ZkProver` / `ZkVerifier`), and compare.
//!
//!   cargo run --release --example identity > identity.txt

use nym_auth_zk_decoy::{threads, AgeRange, Holder, Presentation, Prover, Request, Session, Verifier};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use runtime_random::deterministic::DeterministicRng;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn json(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap()
}

#[allow(clippy::type_complexity)]
fn main() {
    let v = json("decoy_test_vectors.json");
    let v0 = json("decoy_test_vectors_zero_psc.json");
    let syn = json("decoy_synthetic_holders.json");
    let dk: [u8; 32] = hex(v["keys"]["device"]["d"].as_str().unwrap()).try_into().unwrap();
    let issuer = |v: &Value| -> ([u8; 32], [u8; 32]) {
        let k = &v["keys"]["document_signer"];
        (hex(k["x"].as_str().unwrap()).try_into().unwrap(), hex(k["y"].as_str().unwrap()).try_into().unwrap())
    };
    let session = |v: &Value, ch: &str| -> Session {
        let i = &v["sessions"][ch]["inputs"];
        let t = i["jwk_thumbprint"].as_str().map(|s| hex(s).try_into().unwrap());
        if ch == "redirect" {
            Session::Redirect {
                client_id: i["client_id"].as_str().unwrap().into(),
                nonce: i["nonce"].as_str().unwrap().into(),
                jwk_thumbprint: t,
                response_uri: i["response_uri"].as_str().unwrap().into(),
            }
        } else {
            Session::DcApi { origin: i["origin"].as_str().unwrap().into(), nonce: i["nonce"].as_str().unwrap().into(), jwk_thumbprint: t }
        }
    };
    // (name, vectors, credential hex, seed, birth, channel, proof_time, range)
    let mut cases: Vec<(String, &Value, String, String, String, &str, String, Option<&str>)> = Vec::new();
    for (tag, vv) in [("A", &v), ("A0", &v0)] {
        for ch in ["redirect", "dcapi"] {
            cases.push((
                format!("{tag}_{ch}"),
                vv,
                vv["issuer_signed_cbor"].as_str().unwrap().into(),
                vv["holder_openings"]["secret_seed"].as_str().unwrap().into(),
                vv["holder_openings"]["birth_date"].as_str().unwrap().into(),
                ch,
                vv["expected"]["age_check"]["proof_time"].as_str().unwrap().into(),
                Some("13-17"),
            ));
        }
    }
    for (h, t, r) in [("B", "2026-10-27T12:00:00Z", Some("13-17")), ("C", "2026-10-28T09:00:00Z", Some("18+")), ("D", "2026-10-27T12:00:00Z", None)] {
        let d = &syn["holders"][h];
        cases.push((
            h.into(),
            &v,
            d["issuer_signed"].as_str().unwrap().into(),
            d["secret_seed"].as_str().unwrap().into(),
            d["birth_date"].as_str().unwrap().into(),
            "redirect",
            t.into(),
            r,
        ));
    }
    let prover = Prover::load().unwrap();
    let verifier = Verifier::load().unwrap();
    eprintln!("threads {}", threads());
    for (k, (name, vv, cred, seed, birth, ch, t, range)) in cases.into_iter().enumerate() {
        let cred = hex(&cred);
        let holder = Holder { credential: &cred, secret_seed: hex(&seed).try_into().unwrap(), birth_date: birth.as_bytes().try_into().unwrap() };
        let r = Request {
            issuer_key: issuer(vv),
            proof_time: t,
            age_range: range.map(|a| AgeRange::parse(a).unwrap()),
            verifier_id: vv["expected"]["pseudonym_inputs"]["verifier_id"].as_str().unwrap().into(),
            session: session(vv, ch),
        };
        let sig: Signature = SigningKey::from_bytes(&dk.into()).unwrap().sign(&Prover::device_signed_bytes(&r));
        let sig: [u8; 64] = sig.to_bytes().into();
        let p1 = prover.prove(&r, &holder, &sig, &mut DeterministicRng::new(1000 + k as u64)).unwrap();
        let mut rng = DeterministicRng::new(1000 + k as u64);
        let pre = prover.prebuild(&r, &holder, &mut rng).unwrap();
        let p2 = prover.prove_prebuilt(pre, &sig, &mut rng).unwrap();
        assert_eq!(p1, p2, "{name}: prove and the two phases differ");
        let verdict = |p: &Presentation| match verifier.verify(&r, p) {
            Ok(()) => "ok".to_string(),
            Err(e) => format!("{e:?}"),
        };
        println!("{name} proof {} sha256 {} pseudonym {} verify {}", p1.proof.len(), hx(&Sha256::digest(&p1.proof)), hx(&p1.pseudonym), verdict(&p1));
        // Tampered copies: 200 single-byte flips spread over the proof, truncated, extended.
        let n = p1.proof.len();
        let mut flips = std::collections::BTreeMap::<String, usize>::new();
        for j in 0..200 {
            let at = (j * 7919 + k * 31) % n;
            let mut q = p1.clone();
            q.proof[at] ^= 1 << (j % 8);
            *flips.entry(verdict(&q)).or_default() += 1;
        }
        let mut q = p1.clone();
        q.proof.pop();
        let trunc = verdict(&q);
        let mut q = p1.clone();
        q.proof.push(0);
        let ext = verdict(&q);
        println!("{name} flips {flips:?} truncated {trunc} extended {ext}");
    }
}
