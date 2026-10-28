//! The two-phase prover: `prebuild` (before the device signature, while consent shows) and
//! `prove_prebuilt` (after it). The result verifies like `prove`'s; each phase refuses what it can
//! check with its reason; the prebuilt state can move to another thread; `system_id` is the
//! archive's SHA-256.

use nym_auth_zk::{AgeRange, Error, Holder, Prebuilt, Prover, Request, Session, Verifier};
use runtime_random::SecureRandomEngine;
use serde_json::Value;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex(s).try_into().unwrap()
}

struct V(Value);
impl V {
    fn load() -> V {
        let p = format!("{}/tests/data/nym_auth_test_vectors.json", env!("CARGO_MANIFEST_DIR"));
        V(serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap())
    }
    fn s(&self, p: &[&str]) -> String {
        p.iter().fold(&self.0, |x, k| &x[*k]).as_str().unwrap().to_string()
    }
    fn request(&self, range: Option<&str>) -> Request {
        let i = &self.0["sessions"]["redirect"]["inputs"];
        Request {
            issuer_key: (arr(&self.s(&["keys", "document_signer", "x"])), arr(&self.s(&["keys", "document_signer", "y"]))),
            proof_time: self.s(&["expected", "age_check", "proof_time"]),
            age_range: range.map(|r| AgeRange::parse(r).unwrap()),
            verifier_id: self.s(&["expected", "pseudonym_inputs", "verifier_id"]),
            session: Session::Redirect {
                client_id: i["client_id"].as_str().unwrap().into(),
                nonce: i["nonce"].as_str().unwrap().into(),
                jwk_thumbprint: i["jwk_thumbprint"].as_str().map(arr::<32>),
                response_uri: i["response_uri"].as_str().unwrap().into(),
            },
        }
    }
}

#[test]
fn prebuild_then_prove_verifies() {
    let v = V::load();
    let prover = Prover::load().unwrap();
    let verifier = Verifier::load().unwrap();
    let cred = hex(&v.s(&["issuer_signed_cbor"]));
    let holder = Holder {
        credential: &cred,
        secret_seed: arr(&v.s(&["holder_openings", "secret_seed"])),
        birth_date: v.s(&["holder_openings", "birth_date"]).as_bytes().try_into().unwrap(),
    };
    let r = v.request(Some("13-17"));
    let sig = arr::<64>(&v.s(&["sessions", "redirect", "device_signature_r_s"]));
    let rng = &mut SecureRandomEngine::new();

    let pre = prover.prebuild(&r, &holder, rng).unwrap();
    let nym = pre.pseudonym();
    assert_eq!(format!("{pre:?}"), "Prebuilt(..)");
    // The prebuilt state moves to another thread (a wallet prebuilds in the background).
    fn sendable<T: Send>(_: &T) {}
    sendable(&pre);
    let pre: Prebuilt = std::thread::spawn(move || pre).join().unwrap();
    let p = prover.prove_prebuilt(pre, &sig, rng).unwrap();
    assert_eq!(p.pseudonym, nym);
    assert_eq!(nym, arr::<32>(&v.s(&["expected", "pseudonyms_sha256", "known-offender-matching-ssc"])));
    verifier.verify(&r, &p).unwrap();

    // Phase 1 refusals, with their reasons.
    let mut other = holder.secret_seed;
    other[3] ^= 1;
    let h2 = Holder { credential: &cred, secret_seed: other, birth_date: holder.birth_date };
    assert_eq!(prover.prebuild(&r, &h2, rng).err(), Some(Error::Holder("secret_seed and birth_date do not open bsc")));
    assert_eq!(
        prover.prebuild(&v.request(Some("18+")), &holder, rng).err(),
        Some(Error::Holder("birth_date is outside the age range"))
    );
    let mut late = r.clone();
    late.proof_time = "2027-10-27T00:00:01Z".into();
    assert_eq!(prover.prebuild(&late, &holder, rng).err(), Some(Error::Holder("the credential is not valid at proof_time")));
    let mut wrong_issuer = r.clone();
    wrong_issuer.issuer_key = (arr(&v.s(&["keys", "device", "x"])), arr(&v.s(&["keys", "device", "y"])));
    assert_eq!(
        prover.prebuild(&wrong_issuer, &holder, rng).err(),
        Some(Error::Holder("the issuer signature does not verify under the issuer key"))
    );
    // Phase 2 refusal: a signature over another session.
    let pre = prover.prebuild(&r, &holder, rng).unwrap();
    let other_sig = arr::<64>(&v.s(&["sessions", "dcapi", "device_signature_r_s"]));
    assert_eq!(
        prover.prove_prebuilt(pre, &other_sig, rng).err(),
        Some(Error::Holder("the device signature does not verify under the credential's device key"))
    );
}

#[test]
fn system_id_is_the_archive_sha256() {
    assert_eq!(
        nym_auth_zk::system_id(),
        "urn:circuits:sha256:f4d75ee2a112c63adfb00f1da45347c4691085c8cca6ab13cee7b03f00cdbd52"
    );
    assert_eq!(nym_auth_zk::PROOF_SYSTEM, "longfellow-libzk-v1");
}
