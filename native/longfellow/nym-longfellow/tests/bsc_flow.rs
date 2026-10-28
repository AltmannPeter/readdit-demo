//! Rulebook v0.5 end to end on the `nym-auth-zk` bsc circuits, through the holder's three steps
//! (`Prover::sign`, `witness`, `prove`) and `Verifier::verify` with `rulebook: "0.5"`, on the demo
//! holders' v0.5 credentials (`app/wallet/demo-wallet.json`, each holder's `v05`). The package's
//! VERIFIER-AGENT.md §4 lists the cases.

use nym_auth_zk as v5;
use nym_longfellow::circuit::DOC_TYPE;
use nym_longfellow::presentation::{Presentation, ResultValue};
use nym_longfellow::prover::{Prover, SignInput, WitnessInput};
use nym_longfellow::verifier::{Verifier, VerifyInput};
use nym_longfellow::{b64url, bsc, dates, sha256, unb64url, x509};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use runtime_random::SecureRandomEngine;
use serde_json::{Value, json};

fn here(p: &str) -> std::path::PathBuf {
  std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(p)
}

fn root(p: &str) -> std::path::PathBuf {
  here(&format!("../../{p}"))
}

fn json_file(p: std::path::PathBuf) -> Value {
  serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))).unwrap()
}

const THUMBPRINT: [u8; 32] = [0x5a; 32];

fn request(host: &str, nonce: &str, range: Option<&str>) -> Value {
  let mut req = vec![json!({ "fn_id": "pseudonym", "return": "nym", "params": { "config": "known-offender-matching-ssc", "ver": 1, "prf": "sha-256" } })];
  if let Some(r) = range {
    req.push(json!({ "fn_id": "age_check", "params": { "range": r } }));
  }
  json!({
    "client_id": format!("x509_san_dns:{host}"),
    "nonce": nonce,
    "response_uri": format!("https://{host}/api/vp/response/s1"),
    "dcql_query": { "credentials": [{ "id": "nym_attestation", "format": "zkp_req", "meta": { "source_format": "mso_mdoc", "doctype_value": DOC_TYPE }, "_req": req }] },
    "client_metadata": { "vp_formats_supported": { "zkp_req": {
      "system_id_values": ["urn:circuits:longfellow:nym_auth:v1"], "proof_system_values": ["longfellow-libzk-v1"] } } },
  })
}

fn handover(req: &Value) -> Value {
  json!({ "client_id": req["client_id"], "nonce": req["nonce"], "response_uri": req["response_uri"], "jwk_thumbprint": b64url(&THUMBPRINT) })
}

/// A holder of the wallet file as the v0.5 phone sends it: the v0.5 credential, the device key, the
/// seed and the birth date.
#[derive(Clone)]
struct Holder {
  credential: Value,
  device_key: Value,
  secret_seed: String,
  birth_date: String,
}

fn holders(file: std::path::PathBuf) -> Vec<Holder> {
  json_file(file)["holders"]
    .as_array()
    .unwrap()
    .iter()
    .map(|h| Holder {
      credential: h["v05"]["credential"].clone(),
      device_key: h["device_key"].clone(),
      secret_seed: h["secret_seed"].as_str().unwrap().into(),
      birth_date: h["v05"]["birth_date"].as_str().unwrap().into(),
    })
    .collect()
}

fn present(p: &Prover, h: &Holder, req: &Value) -> Result<Value, nym_longfellow::error::Refusal> {
  let sign: SignInput = serde_json::from_value(json!({ "device_key": h.device_key, "doc_type": DOC_TYPE, "handover": handover(req) })).unwrap();
  let signed = p.sign(&sign)?;
  let input: WitnessInput = serde_json::from_value(json!({
    "system_id": "urn:circuits:longfellow:nym_auth:v1", "credential_query_id": "nym_attestation",
    "request": req, "handover": handover(req), "credential": h.credential,
    "secret_seed": h.secret_seed, "birth_date": h.birth_date, "device_signature": signed.device_signature, "rulebook": "0.5",
  }))
  .unwrap();
  let w = p.witness(&input)?;
  Ok(p.prove(w).unwrap())
}

fn verify_with(v: &Verifier, req: &Value, presentation: &str, now: &str, learned: &[String]) -> Value {
  let input: VerifyInput = serde_json::from_value(json!({
    "request": req, "credential_query_id": "nym_attestation", "presentation": presentation, "handover": handover(req),
    "now": now, "learned_issuers": learned, "rulebook": "0.5",
  }))
  .unwrap();
  v.verify(&input)
}

fn verify(v: &Verifier, req: &Value, presentation: &str, now: &str) -> Value {
  verify_with(v, req, presentation, now, &[])
}

fn now_plus(s: i64) -> String {
  dates::from_unix(dates::unix(&dates::now().unwrap()) + s).unwrap().text()
}

fn age_on(birth: &str, today: &dates::Date) -> u32 {
  let b = dates::date(birth).unwrap();
  today.year - b.year - u32::from((today.month, today.day) < (b.month, b.day))
}

fn code(v: &Value) -> &str {
  v["code"].as_str().unwrap_or("ok")
}

fn edit(presentation: &str, f: impl FnOnce(&mut Presentation)) -> String {
  let mut p = Presentation::decode(&unb64url("p", presentation).unwrap()).unwrap();
  f(&mut p);
  b64url(&p.encode().unwrap())
}

#[test]
fn v05_holders_prove_and_the_verifier_refuses() {
  let dir = here("circuits/mdoc");
  let prover = Prover::load(&dir).unwrap();
  let pem = std::fs::read_to_string(root("native/vega/demo/document-signer.pem")).unwrap();
  let verifier = Verifier::load(&dir, &pem, 300).unwrap();
  let all = holders(root("app/wallet/demo-wallet.json"));
  let today = dates::now().unwrap().date;
  let teen = all.iter().find(|h| (13..=17).contains(&age_on(&h.birth_date, &today))).expect("a teen").clone();
  let adult = all.iter().find(|h| age_on(&h.birth_date, &today) >= 18).expect("an adult").clone();

  // Accepted: every holder without an age check, and in the range it fits.
  for h in &all {
    let fits = if age_on(&h.birth_date, &today) >= 18 { "18+" } else { "13-17" };
    for range in [None, Some(fits)] {
      let req = request("community.example", "v05-accept-0123456789abcdef012345", range);
      let out = present(&prover, h, &req).unwrap_or_else(|e| panic!("{} {range:?}: {e:?}", h.birth_date));
      let pres = out["presentation"].as_str().unwrap();
      let v = verify(&verifier, &req, pres, &dates::now().unwrap().text());
      assert_eq!(v["ok"], true, "{} {range:?}: {v}", h.birth_date);
      let seed: [u8; 16] = nym_longfellow::unhex("seed", &h.secret_seed).unwrap();
      assert_eq!(v["results"]["nym"].as_str().unwrap(), nym_longfellow::hex(&v5::witness::pseudonym(&seed, &sha256(b"x509_san_dns:community.example"))));
      assert_eq!(v["results"].as_object().unwrap().len(), 1, "an assertion has no output");
      assert_eq!(v["bounds"].is_null(), range.is_none(), "{v}");
      println!("{} {range:?}: proof {} B, prove {} ms, verify {} ms", h.birth_date, out["metrics"]["proof_bytes"], out["metrics"]["prove_ms"], v["metrics"]["verify_ms"]);
    }
  }

  let req = request("community.example", "v05-refuse-0123456789abcdef012345", Some("13-17"));
  let out = present(&prover, &teen, &req).unwrap();
  let pres = out["presentation"].as_str().unwrap().to_string();
  let now = dates::now().unwrap().text();
  // proof_time within the tolerance.
  assert_eq!(verify(&verifier, &req, &pres, &now_plus(120))["ok"], true);

  // Refused by the verifier.
  let other_nonce = request("community.example", "v05-another-nonce-0123456789abcd", Some("13-17"));
  assert_eq!(code(&verify(&verifier, &other_nonce, &pres, &now)), "proof_invalid");
  let other_client = request("other.example", "v05-refuse-0123456789abcdef012345", Some("13-17"));
  assert_eq!(code(&verify(&verifier, &other_client, &pres, &now)), "proof_invalid");
  let other_range = request("community.example", "v05-refuse-0123456789abcdef012345", Some("14-17"));
  let r = verify(&verifier, &other_range, &pres, &now);
  assert_eq!((code(&r), r["input"].as_str()), ("proof_invalid", Some("hash")), "{r}");
  let tampered = edit(&pres, |p| p.proof[1000] ^= 1);
  assert!(matches!(code(&verify(&verifier, &req, &tampered, &now)), "proof_invalid" | "proof_encoding"));
  let truncated = edit(&pres, |p| p.proof.truncate(p.proof.len() / 2));
  assert_eq!(code(&verify(&verifier, &req, &truncated, &now)), "proof_encoding");
  assert_eq!(code(&verify(&verifier, &req, &pres, &now_plus(3600))), "proof_time");
  let missing = edit(&pres, |p| p.results[0].0 = "pseudonym".into());
  assert_eq!(code(&verify(&verifier, &req, &missing, &now)), "results");
  let extra = edit(&pres, |p| p.results.push(("age".into(), ResultValue::True)));
  assert_eq!(code(&verify(&verifier, &req, &extra, &now)), "results");
  let other_nym = edit(&pres, |p| p.results[0].1 = ResultValue::Pseudonym([7; 32]));
  assert_eq!(code(&verify(&verifier, &req, &other_nym, &now)), "proof_invalid");
  // Read as v0.4, the request lacks the age check's return handle.
  let as04: VerifyInput = serde_json::from_value(json!({
    "request": req, "credential_query_id": "nym_attestation", "presentation": pres, "handover": handover(&req), "now": now, "rulebook": "0.4",
  }))
  .unwrap();
  assert_eq!(code(&verifier.verify(&as04)), "request");

  // An unknown issuer: refused with its certificate, accepted once learned.
  let other = holders(root("scripts/fixtures/other-issuer-wallet.json")).remove(0);
  let req2 = request("community.example", "v05-issuer-0123456789abcdef012345", None);
  let out2 = present(&prover, &other, &req2).unwrap();
  let pres2 = out2["presentation"].as_str().unwrap();
  let r = verify(&verifier, &req2, pres2, &now);
  assert_eq!(code(&r), "issuer_key_set", "{r}");
  let cert = r["certificate"].as_str().expect("the untrusted certificate").to_string();
  assert_eq!(verify_with(&verifier, &req2, pres2, &now, &[cert])["ok"], true);

  // Refused by the prover.
  let r18 = request("community.example", "v05-prover-0123456789abcdef0123456", Some("18+"));
  assert_eq!(present(&prover, &teen, &r18).unwrap_err().error, "unsatisfiable");
  assert_eq!(present(&prover, &adult, &req).unwrap_err().error, "unsatisfiable");
  let expired = holders(here("nym-longfellow/tests/data/v05-expired-wallet.json")).remove(0);
  let e = present(&prover, &expired, &req).unwrap_err();
  assert_eq!(e.error, "unsatisfiable", "{e:?}");
  let wrong_seed = Holder { secret_seed: "00".repeat(16), ..teen.clone() };
  assert_eq!(present(&prover, &wrong_seed, &req).unwrap_err().error, "bad_credential");
  let wrong_birth = Holder { birth_date: "2011-03-15".into(), ..teen.clone() };
  assert_eq!(present(&prover, &wrong_birth, &req).unwrap_err().error, "bad_credential");
  let v04 = json_file(root("app/wallet/demo-wallet.json"))["holders"][0]["credential"].clone();
  let old = Holder { credential: v04, ..teen.clone() };
  assert_eq!(present(&prover, &old, &req).unwrap_err().error, "bad_credential");
}

/// validUntil is inclusive (rulebook v0.5): the rulebook vector's credential proves at
/// proof_time = validUntil and the verifier accepts it at that time; one second later the crate
/// refuses to prove (`Unsatisfied`). Fixed times, through the crate's prover (the addon's takes the clock).
#[test]
fn valid_until_is_inclusive() {
  let dir = here("circuits/mdoc");
  let vectors = json_file(root("profiles/nym-auth-v0.5/test-vectors/nym_auth_mdoc/nym_auth_test_vectors.json"));
  let s = |p: &[&str]| p.iter().fold(&vectors, |x, k| &x[*k]).as_str().unwrap().to_string();
  // The vector's Document Signer is issued by its IACA, not self-signed: the verifier takes it as a
  // learned issuer (/tech's Trust new issuers).
  let der = hex::decode(s(&["keys", "document_signer", "cert_der"])).unwrap();
  let learned = {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(&der)
  };
  let pem = std::fs::read_to_string(root("native/vega/demo/document-signer.pem")).unwrap();
  let verifier = Verifier::load(&dir, &pem, 300).unwrap();
  let signer = x509::parse(&der).unwrap();
  let until = s(&["mso", "validity", "validUntil"]);
  let req = request("community.example", "v05-until-0123456789abcdef0123456", Some("13-17"));
  let ro: nym_longfellow::request::RequestObject = serde_json::from_value(req.clone()).unwrap();
  let h: nym_longfellow::handover::Handover = serde_json::from_value(handover(&req)).unwrap();
  let device = SigningKey::from_bytes(&<[u8; 32]>::try_from(hex::decode(s(&["keys", "device", "d"])).unwrap()).unwrap().into()).unwrap();
  let credential = hex::decode(s(&["issuer_signed_cbor"])).unwrap();
  let holder = v5::Holder {
    credential: &credential,
    secret_seed: hex::decode(s(&["holder_openings", "secret_seed"])).unwrap().try_into().unwrap(),
    birth_date: s(&["holder_openings", "birth_date"]).as_bytes().try_into().unwrap(),
  };
  let prover = v5::Prover::load().unwrap();
  let prove_at = |t: &str| {
    let r = bsc::request(&signer.key, t, &ro, "nym_attestation", &h).unwrap();
    let sig: Signature = device.sign(&v5::Prover::device_signed_bytes(&r));
    prover.prove(&r, &holder, &sig.to_bytes().into(), &mut SecureRandomEngine::new())
  };
  let p = prove_at(&until).expect("proves at validUntil");
  let wire = Presentation {
    system_id: "urn:circuits:longfellow:nym_auth:v1".into(),
    proof: p.proof,
    issuer_key_set: vec![der.clone()],
    proof_time: until.clone(),
    results: vec![("nym".into(), ResultValue::Pseudonym(p.pseudonym))],
  };
  let v = verify_with(&verifier, &req, &b64url(&wire.encode().unwrap()), &until, &[learned]);
  assert_eq!(v["ok"], true, "{v}");
  let after = dates::from_unix(dates::unix(&dates::date_time(&until).unwrap()) + 1).unwrap().text();
  assert_eq!(prove_at(&after).unwrap_err(), v5::Error::Unsatisfied);
}
