//! Rulebook v0.5 end to end on the Vega `bsc` circuits (`circuits/mdoc-bsc/shapes.zst`), through
//! the holder's three steps (`Prover::sign`, `witness`, which prepares, and `prove`) and
//! `Verifier::verify` with `rulebook: "0.5"`, on the demo holders' v0.5 credentials
//! (`app/wallet/demo-wallet.json`, each holder's `v05`). The package's VERIFIER-AGENT.md §4 lists
//! the cases. Run with `--release`: each test builds the keys and proves.

use std::path::{Path, PathBuf};

use nym_vega::circuit::{CIRCUIT_ID, CIRCUIT_ID_V05, DOC_TYPE};
use nym_vega::handover::{self, Handover};
use nym_vega::presentation::{Presentation, ResultValue};
use nym_vega::prover::{Prover, SignInput, WitnessInput};
use nym_vega::request::{RequestObject, Rulebook, statement_for};
use nym_vega::verifier::{Verifier, VerifyInput};
use nym_vega::{b64url, bsc, dates, hex, mdoc, unb64url, unhex, x509};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value, json};
use vega_age::app;

fn root(p: &str) -> PathBuf {
  Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..").join(p)
}

fn json_file(p: PathBuf) -> Value {
  serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))).unwrap()
}

const V04: &str = "native/vega/circuits/mdoc/shapes.zst";
const V05: &str = "native/vega/circuits/mdoc-bsc/shapes.zst";
const THUMBPRINT: [u8; 32] = [0x5a; 32];

fn load() -> (Prover, Verifier) {
  let pem = std::fs::read_to_string(root("native/vega/demo/document-signer.pem")).unwrap();
  let (v04, v05) = (root(V04), root(V05));
  (Prover::load(&v04, Some(&v05)).unwrap(), Verifier::load(&v04, Some(&v05), &pem, 300).unwrap())
}

fn request(host: &str, nonce: &str, range: Option<&str>, offered: &str) -> Value {
  let mut req = vec![json!({ "fn_id": "pseudonym", "return": "nym", "params": { "config": "known-offender-matching-ssc", "ver": 1, "prf": "sha-256" } })];
  if let Some(r) = range {
    req.push(json!({ "fn_id": "age_check", "params": { "range": r } }));
  }
  json!({
    "client_id": format!("x509_san_dns:{host}"),
    "nonce": nonce,
    "response_uri": format!("https://{host}/api/vp/response/s1"),
    "dcql_query": { "credentials": [{ "id": "nym_attestation", "format": "zkp_req", "meta": { "source_format": "mso_mdoc", "doctype_value": DOC_TYPE }, "_req": req }] },
    "client_metadata": { "vp_formats_supported": { "zkp_req": { "system_id_values": [offered], "proof_system_values": ["vega-v1"] } } },
  })
}

fn handover_json(req: &Value) -> Value {
  json!({ "client_id": req["client_id"], "nonce": req["nonce"], "response_uri": req["response_uri"], "jwk_thumbprint": b64url(&THUMBPRINT) })
}

/// A holder of a wallet file as the v0.5 phone sends it: the v0.5 credential, the device key, the
/// seed and the birth date.
#[derive(Clone)]
struct Holder {
  credential: Value,
  device_key: Value,
  secret_seed: String,
  birth_date: String,
}

fn holders(file: PathBuf) -> Vec<Holder> {
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

fn present_as(p: &Prover, h: &Holder, req: &Value, system_id: &str, rulebook: &str) -> Result<Value, nym_vega::error::Refusal> {
  let sign: SignInput = serde_json::from_value(json!({ "device_key": h.device_key, "doc_type": DOC_TYPE, "handover": handover_json(req) })).unwrap();
  let signed = p.sign(&sign)?;
  let input: WitnessInput = serde_json::from_value(json!({
    "system_id": system_id, "credential_query_id": "nym_attestation",
    "request": req, "handover": handover_json(req), "credential": h.credential,
    "secret_seed": h.secret_seed, "birth_date": h.birth_date, "device_signature": signed.device_signature, "rulebook": rulebook,
  }))
  .unwrap();
  let w = p.witness(&input)?;
  Ok(p.prove(w).unwrap())
}

fn present(p: &Prover, h: &Holder, req: &Value) -> Result<Value, nym_vega::error::Refusal> {
  present_as(p, h, req, CIRCUIT_ID_V05, "0.5")
}

fn verify_as(v: &Verifier, req: &Value, presentation: &str, now: &str, learned: &[String], rulebook: &str) -> Value {
  let input: VerifyInput = serde_json::from_value(json!({
    "request": req, "credential_query_id": "nym_attestation", "presentation": presentation, "handover": handover_json(req),
    "now": now, "learned_issuers": learned, "rulebook": rulebook,
  }))
  .unwrap();
  v.verify(&input)
}

fn verify(v: &Verifier, req: &Value, presentation: &str, now: &str) -> Value {
  verify_as(v, req, presentation, now, &[], "0.5")
}

fn now_plus(s: i64) -> String {
  dates::from_unix(dates::unix(&dates::now().unwrap()).unwrap() + s).unwrap().text()
}

fn age_on(birth: &str, today: &vega_age::presentation::Date) -> u32 {
  let b = dates::date(birth).unwrap();
  today.year - b.year - u32::from((today.month, today.day) < (b.month, b.day))
}

fn refusal(v: &Value) -> (&str, Option<&str>) {
  (v["code"].as_str().unwrap_or("ok"), v["input"].as_str())
}

fn edit(presentation: &str, f: impl FnOnce(&mut Presentation)) -> String {
  let mut p = Presentation::decode(&unb64url("p", presentation).unwrap()).unwrap();
  f(&mut p);
  b64url(&p.encode().unwrap())
}

#[test]
fn v05_holders_prove_and_the_verifier_refuses() {
  let (prover, verifier) = load();
  let info = verifier.info();
  let ids: Vec<&str> = info["circuits"].as_array().unwrap().iter().map(|c| c["system_id"].as_str().unwrap()).collect();
  assert_eq!(ids, [CIRCUIT_ID, CIRCUIT_ID_V05]);
  let all = holders(root("app/wallet/demo-wallet.json"));
  let today = dates::now().unwrap().date;
  let teen = all.iter().find(|h| (13..=17).contains(&age_on(&h.birth_date, &today))).expect("a teen").clone();
  let adult = all.iter().find(|h| age_on(&h.birth_date, &today) >= 18).expect("an adult").clone();
  let offered = CIRCUIT_ID_V05;

  // Accepted: every holder without an age check, and in the range it fits; the pseudonym is the
  // one the v0.4 circuits give (one seed opens ssc and bsc).
  for h in &all {
    let fits = if age_on(&h.birth_date, &today) >= 18 { "18+" } else { "13-17" };
    for range in [None, Some(fits)] {
      let req = request("community.example", "v05-accept-0123456789abcdef012345", range, offered);
      let out = present(&prover, h, &req).unwrap_or_else(|e| panic!("{} {range:?}: {e:?}", h.birth_date));
      assert_eq!(out["system_id"], CIRCUIT_ID_V05);
      let m = &out["metrics"];
      assert!(m["prebuild_ms"].as_f64().unwrap() <= m["witness_ms"].as_f64().unwrap(), "{m}");
      let pres = out["presentation"].as_str().unwrap();
      let v = verify(&verifier, &req, pres, &dates::now().unwrap().text());
      assert_eq!(v["ok"], true, "{} {range:?}: {v}", h.birth_date);
      let seed: [u8; 16] = unhex("seed", &h.secret_seed).unwrap();
      let expected = vega_age::pseudonym::pseudonym(&seed, &vega_age::pseudonym::verifier_input("x509_san_dns:community.example"));
      assert_eq!(v["results"]["nym"].as_str().unwrap(), hex(&expected));
      assert_eq!(v["results"].as_object().unwrap().len(), 1, "an assertion has no output");
      assert_eq!(v["bounds"].is_null(), range.is_none(), "{v}");
      println!(
        "{} {range:?}: proof {} B, prepare {} ms, prove {} ms, verify {} ms",
        h.birth_date, m["proof_bytes"], m["prebuild_ms"], m["prove_ms"], v["metrics"]["verify_ms"]
      );
    }
  }

  let req = request("community.example", "v05-refuse-0123456789abcdef012345", Some("13-17"), offered);
  let out = present(&prover, &teen, &req).unwrap();
  let pres = out["presentation"].as_str().unwrap().to_string();
  let now = dates::now().unwrap().text();
  // proof_time within the tolerance.
  assert_eq!(verify(&verifier, &req, &pres, &now_plus(120))["ok"], true);

  // Refused by the verifier, each naming its input.
  let other_nonce = request("community.example", "v05-another-nonce-0123456789abcd", Some("13-17"), offered);
  assert_eq!(refusal(&verify(&verifier, &other_nonce, &pres, &now)), ("public_input", Some("session_transcript")));
  let other_client = request("other.example", "v05-refuse-0123456789abcdef012345", Some("13-17"), offered);
  assert_eq!(refusal(&verify(&verifier, &other_client, &pres, &now)), ("public_input", Some("session_transcript")));
  let other_min = request("community.example", "v05-refuse-0123456789abcdef012345", Some("14-17"), offered);
  assert_eq!(refusal(&verify(&verifier, &other_min, &pres, &now)), ("public_input", Some("age_check.le")));
  let other_max = request("community.example", "v05-refuse-0123456789abcdef012345", Some("13-16"), offered);
  assert_eq!(refusal(&verify(&verifier, &other_max, &pres, &now)), ("public_input", Some("age_check.ge")));
  let other_nym = edit(&pres, |p| {
    if let ResultValue::Pseudonym(n) = &mut p.results[0].1 {
      n[5] ^= 1;
    }
  });
  assert_eq!(refusal(&verify(&verifier, &req, &other_nym, &now)), ("public_input", Some("results.nym")));
  let tampered = edit(&pres, |p| {
    let at = p.proof.len() / 2;
    p.proof[at] ^= 1;
  });
  assert!(matches!(refusal(&verify(&verifier, &req, &tampered, &now)).0, "proof_invalid" | "proof_encoding"));
  let truncated = edit(&pres, |p| p.proof.truncate(p.proof.len() / 2));
  assert_eq!(refusal(&verify(&verifier, &req, &truncated, &now)).0, "proof_encoding");
  assert_eq!(refusal(&verify(&verifier, &req, &pres, &now_plus(3600))).0, "proof_time");
  // v0.5 allows an empty results map; these circuits still need the pseudonym's handle.
  for (what, changed) in [
    ("empty", edit(&pres, |p| p.results.clear())),
    ("missing", edit(&pres, |p| p.results[0].0 = "pseudonym".into())),
    ("extra", edit(&pres, |p| p.results.push(("age".into(), ResultValue::True)))),
  ] {
    assert_eq!(refusal(&verify(&verifier, &req, &changed, &now)).0, "results", "{what}");
  }
  // The circuit: read as v0.4, named as v0.4's circuits, or not offered.
  assert_eq!(refusal(&verify_as(&verifier, &req, &pres, &now, &[], "0.4")).0, "circuit");
  assert_eq!(refusal(&verify(&verifier, &req, &edit(&pres, |p| p.system_id = CIRCUIT_ID.into()), &now)).0, "circuit");
  let not_offered = request("community.example", "v05-refuse-0123456789abcdef012345", Some("13-17"), CIRCUIT_ID);
  assert_eq!(refusal(&verify(&verifier, &not_offered, &pres, &now)).0, "circuit");

  // An unknown issuer: refused with its certificate, accepted once learned.
  let other = holders(root("scripts/fixtures/other-issuer-wallet.json")).remove(0);
  let req2 = request("community.example", "v05-issuer-0123456789abcdef012345", None, offered);
  let out2 = present(&prover, &other, &req2).unwrap();
  let pres2 = out2["presentation"].as_str().unwrap();
  let r = verify(&verifier, &req2, pres2, &now);
  assert_eq!(refusal(&r).0, "issuer_key_set", "{r}");
  let cert = r["certificate"].as_str().expect("the untrusted certificate").to_string();
  assert_eq!(verify_as(&verifier, &req2, pres2, &now, &[cert], "0.5")["ok"], true);

  // Refused by the prover.
  let r18 = request("community.example", "v05-prover-0123456789abcdef0123456", Some("18+"), offered);
  assert_eq!(present(&prover, &teen, &r18).unwrap_err().error, "unsatisfiable");
  assert_eq!(present(&prover, &adult, &req).unwrap_err().error, "unsatisfiable");
  let expired = holders(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/v05-expired-wallet.json")).remove(0);
  let e = present(&prover, &expired, &req).unwrap_err();
  assert_eq!(e.error, "unsatisfiable", "{e:?}");
  let wrong_seed = Holder { secret_seed: "00".repeat(16), ..teen.clone() };
  assert_eq!(present(&prover, &wrong_seed, &req).unwrap_err().error, "bad_credential");
  let wrong_birth = Holder { birth_date: "2011-03-15".into(), ..teen.clone() };
  assert_eq!(present(&prover, &wrong_birth, &req).unwrap_err().error, "bad_credential");
  let v04 = json_file(root("app/wallet/demo-wallet.json"))["holders"][0]["credential"].clone();
  let old = Holder { credential: v04, ..teen.clone() };
  assert_eq!(present(&prover, &old, &req).unwrap_err().error, "bad_credential");
  let other_device = Holder { device_key: all.iter().find(|h| h.birth_date != teen.birth_date).unwrap().device_key.clone(), ..teen.clone() };
  assert_eq!(present(&prover, &other_device, &req).unwrap_err().error, "bad_credential");
  // Each set of circuits reads its own rulebook version.
  assert_eq!(present_as(&prover, &teen, &req, CIRCUIT_ID, "0.5").unwrap_err().error, "unsupported_circuit");
  assert_eq!(present_as(&prover, &teen, &req, CIRCUIT_ID_V05, "0.4").unwrap_err().error, "unsupported_circuit");
  assert_eq!(present(&prover, &teen, &not_offered).unwrap_err().error, "unsupported_circuit");
}

/// validUntil is inclusive (rulebook v0.5): the rulebook vector's credential proves at
/// proof_time = validUntil and the verifier accepts it at that time; one second later the circuits
/// refuse it ("not expired"). Fixed times, through the adapter (the prover takes the clock).
#[test]
fn valid_until_is_inclusive() {
  let (_, verifier) = load();
  let vectors = json_file(root("profiles/nym-auth-v0.5/test-vectors/nym_auth_mdoc/nym_auth_test_vectors.json"));
  let s = |p: &[&str]| p.iter().fold(&vectors, |x, k| &x[*k]).as_str().unwrap().to_string();
  // The vector's Document Signer is issued by its IACA, not self-signed: the verifier takes it as a
  // learned issuer (/tech's Trust new issuers).
  let der = ::hex::decode(s(&["keys", "document_signer", "cert_der"])).unwrap();
  let learned = {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(&der)
  };
  let until = s(&["mso", "validity", "validUntil"]);
  let req = request("community.example", "v05-until-0123456789abcdef0123456", Some("13-17"), CIRCUIT_ID_V05);
  let ro: RequestObject = serde_json::from_value(req.clone()).unwrap();
  let h: Handover = serde_json::from_value(handover_json(&req)).unwrap();
  let m = mdoc::parse(&b64url(&::hex::decode(s(&["issuer_signed_cbor"])).unwrap())).unwrap();
  let key = x509::parse(&der).unwrap().key;
  let seed: [u8; 16] = ::hex::decode(s(&["holder_openings", "secret_seed"])).unwrap().try_into().unwrap();
  let birth: [u8; 10] = s(&["holder_openings", "birth_date"]).as_bytes().try_into().unwrap();
  let device = SigningKey::from_bytes(::hex::decode(s(&["keys", "device", "d"])).unwrap().as_slice().into()).unwrap();
  let (pk, _) = bsc::keys(&std::fs::read(root(V05)).unwrap()).unwrap();

  let core_at = |t: &str| {
    let t = dates::date_time(t).unwrap();
    let st = statement_for(&ro, "nym_attestation", &h, Rulebook::V05, Some(t.date)).unwrap();
    let sig: Signature = device.sign(&handover::device_message(&st.session_transcript, DOC_TYPE));
    let nym = bsc::pseudonym_for(&seed, &st);
    let w = bsc::witness(&m, key, &seed, &birth, &st).unwrap();
    (bsc::core(w, bsc::public(key, &st, t, nym).unwrap(), &sig.to_bytes().into()), nym)
  };
  let (core, nym) = core_at(&until);
  let steps = app::steps(&core.witness.as_ref().unwrap().table);
  let unsigned = vega_age::bsc::BscCore { presentation: None, ..core.clone() };
  let prepared = app::prepare(&pk, &steps, &unsigned).unwrap();
  let (proof, _) = app::prove(&pk, &steps, &core, prepared).unwrap();
  let wire = Presentation {
    system_id: CIRCUIT_ID_V05.into(),
    proof: bincode::serialize(&proof).unwrap(),
    issuer_key_set: vec![der.clone()],
    proof_time: until.clone(),
    results: vec![("nym".into(), ResultValue::Pseudonym(nym))],
  };
  let v = verify_as(&verifier, &req, &b64url(&wire.encode().unwrap()), &until, &[learned], "0.5");
  assert_eq!(v["ok"], true, "{v}");
  let after = dates::from_unix(dates::unix(&dates::date_time(&until).unwrap()).unwrap() + 1).unwrap().text();
  let broken = app::first_broken(&core_at(&after).0).unwrap();
  assert!(broken.as_deref().is_some_and(|b| b.contains("not expired")), "{broken:?}");
}
