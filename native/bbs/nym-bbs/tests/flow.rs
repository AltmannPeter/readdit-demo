//! End to end on the demo credential: prove, verify, and the refusals.
//! Reads `app/wallet/demo-wallet-bbs.json` and `native/bbs/demo/issuer-params.bin`.

use nym_bbs::presentation::{Presentation, ResultValue};
use nym_bbs::prover::{ProveInput, Prover};
use nym_bbs::verifier::{VerifyInput, Verifier};
use serde_json::{json, Value};

fn root(p: &str) -> String {
  format!("{}/../../../{p}", env!("CARGO_MANIFEST_DIR"))
}

fn wallet() -> Value {
  serde_json::from_str(&std::fs::read_to_string(root("app/wallet/demo-wallet-bbs.json")).unwrap()).unwrap()
}

fn request(host: &str, nonce: &str, age: Option<Value>) -> Value {
  let mut req = vec![json!({ "fn_id": "pseudonym", "return": "nym", "params": { "config": "known-offender-matching-ssc", "ver": 1, "prf": "hashdh-bls12381g1" } })];
  if let Some(a) = age {
    req.push(json!({ "fn_id": "age_check", "return": "age", "params": a }));
  }
  json!({
    "client_id": format!("x509_san_dns:{host}"),
    "nonce": nonce,
    "response_uri": format!("https://{host}/api/vp/response/s1"),
    "dcql_query": { "credentials": [{ "id": "nym_attestation_bbs", "format": "zkp_req",
      "meta": { "source_format": "bbs_cd", "schema_id_value": "eu.europa.ec.eudi.nym_auth.bbs.1" }, "_req": req }] },
    "client_metadata": { "vp_formats_supported": { "zkp_req": { "proof_system_values": ["bbs-cd-plugins-v0.1"], "system_id_values": ["urn:mms:bbs-cd:nym_auth:v1"] } } },
  })
}

fn handover(req: &Value) -> Value {
  json!({ "client_id": req["client_id"], "nonce": req["nonce"], "response_uri": req["response_uri"], "jwk_thumbprint": null })
}

fn prove(p: &Prover, req: &Value) -> Result<Value, nym_bbs::error::Refusal> {
  let w = wallet();
  let input: ProveInput = serde_json::from_value(json!({
    "request": req, "credential_query_id": "nym_attestation_bbs", "handover": handover(req),
    "credential": w["holders"][0]["credential"], "device_key": w["holders"][0]["device_key"],
  }))
  .unwrap();
  p.prove(&input)
}

fn verify(v: &Verifier, req: &Value, presentation: &str) -> Value {
  let input: VerifyInput = serde_json::from_value(json!({
    "request": req, "credential_query_id": "nym_attestation_bbs", "presentation": presentation, "handover": handover(req),
  }))
  .unwrap();
  v.verify(&input)
}

#[test]
fn prove_verify_and_refusals() {
  let prover = Prover::load();
  let verifier = Verifier::load(&std::fs::read(root("native/bbs/demo/issuer-params.bin")).unwrap()).unwrap();

  // Teen, 13 to 17 on 2026-10-19.
  let teen = json!({ "ge": "2008-10-20", "le": "2013-10-19" });
  let req = request("community.example", "0123456789abcdef0123456789abcdef", Some(teen.clone()));
  let out = prove(&prover, &req).expect("prove");
  let pres = out["presentation"].as_str().unwrap();
  let v = verify(&verifier, &req, pres);
  assert_eq!(v["ok"], true, "{v}");
  assert_eq!(v["results"]["age"], true);
  let nym = v["results"]["nym"].as_str().unwrap().to_string();
  assert_eq!(nym.len(), 96);
  assert_eq!(out["results"]["nym"], v["results"]["nym"]);
  // The rulebook's hashdh-bls12381g1, computed here: nym = seed·OP,
  // OP = hash_to_curve_G1(u8(len(config)) ‖ config ‖ UTF-8(client_id), "BBS-CD-PLUGINS/0.1/PSEUDONYM/OP"),
  // seed = hash_to_scalar(secret_seed, "nym_auth/v1/bbs-seed").
  {
    use bbs_cd::params::Ciphersuite;
    use bbs_cd::primitives::{hash_to_curve_g1, point_to_octets_E1, scalar_from_octets};
    let w = wallet();
    let secret_seed = hex::decode(w["holders"][0]["secret_seed"].as_str().unwrap()).unwrap();
    let seed = bbs_cd::utils::hash_to_scalar(Ciphersuite::Sha256, &secret_seed, b"nym_auth/v1/bbs-seed").unwrap().0;
    let config = b"known-offender-matching-ssc";
    let mut msg = vec![config.len() as u8];
    msg.extend(config);
    msg.extend(b"x509_san_dns:community.example");
    let op = hash_to_curve_g1(Ciphersuite::Sha256, &msg, b"BBS-CD-PLUGINS/0.1/PSEUDONYM/OP").unwrap();
    assert_eq!(hex::encode(point_to_octets_E1(&(op * scalar_from_octets(&seed).unwrap()))), nym);
  }

  // The same pseudonym in a new request to the same site, without age.
  let req2 = request("community.example", "fedcba9876543210fedcba9876543210", None);
  let out2 = prove(&prover, &req2).expect("prove");
  let v2 = verify(&verifier, &req2, out2["presentation"].as_str().unwrap());
  assert_eq!(v2["ok"], true, "{v2}");
  assert_eq!(v2["results"]["nym"].as_str().unwrap(), nym);
  assert!(v2["results"].get("age").is_none());

  // Another verifier identity, another pseudonym.
  let req3 = request("france.community.example", "fedcba9876543210fedcba9876543210", None);
  let out3 = prove(&prover, &req3).expect("prove");
  let v3 = verify(&verifier, &req3, out3["presentation"].as_str().unwrap());
  assert_eq!(v3["ok"], true, "{v3}");
  assert_ne!(v3["results"]["nym"].as_str().unwrap(), nym);

  // 18+: the teen cannot.
  let adult = request("community.example", "0123456789abcdef0123456789abcdef", Some(json!({ "le": "2008-10-19" })));
  assert_eq!(prove(&prover, &adult).unwrap_err().error, "unsatisfiable");

  // The presentation against another nonce, another response_uri, another site: refused.
  let mut other = req.clone();
  other["nonce"] = json!("ffffffffffffffffffffffffffffffff");
  assert_eq!(verify(&verifier, &other, pres)["code"], "proof_invalid");
  let mut other = req.clone();
  other["response_uri"] = json!("https://community.example/api/vp/response/s2");
  assert_eq!(verify(&verifier, &other, pres)["code"], "proof_invalid");
  let other = request("france.community.example", "0123456789abcdef0123456789abcdef", Some(teen.clone()));
  assert_eq!(verify(&verifier, &other, pres)["code"], "proof_invalid");
  // Against the same request without the age check (fewer plugins): refused.
  let fewer = request("community.example", "0123456789abcdef0123456789abcdef", None);
  assert_ne!(verify(&verifier, &fewer, pres)["ok"], true);

  // A flipped byte anywhere in the envelope.
  let zkp = Presentation::decode(&nym_bbs::unb64url("p", pres).unwrap()).unwrap();
  let encode = |p: &Presentation| nym_bbs::b64url(&p.encode().unwrap());
  assert_eq!(verify(&verifier, &req, &encode(&zkp))["ok"], true);
  let mut flipped = zkp.clone();
  for at in [10, flipped.proof.len() / 2, flipped.proof.len() - 5] {
    flipped.proof[at] ^= 1;
    let v = verify(&verifier, &req, &encode(&flipped));
    assert_ne!(v["ok"], true, "flip at {at}");
    flipped.proof[at] ^= 1;
  }
  assert_eq!(verify(&verifier, &req, "!!")["code"], "presentation");

  // results: another pseudonym (the one for c/france), a missing or an extra key.
  let mut other_nym = zkp.clone();
  let france: [u8; 48] = hex::decode(v3["results"]["nym"].as_str().unwrap()).unwrap().try_into().unwrap();
  other_nym.results[0].1 = ResultValue::Pseudonym(france);
  assert_eq!(verify(&verifier, &req, &encode(&other_nym))["code"], "results");
  let mut missing = zkp.clone();
  missing.results.pop();
  assert_eq!(verify(&verifier, &req, &encode(&missing))["code"], "results");
  let mut extra = zkp.clone();
  extra.results.push(("more".into(), ResultValue::True));
  assert_eq!(verify(&verifier, &req, &encode(&extra))["code"], "results");
  // issuer_key_set: another key, two keys; system_id: another system; proof_time: not in bbs_cd.
  let mut key = zkp.clone();
  key.issuer_key_set[0][5] ^= 1;
  assert_eq!(verify(&verifier, &req, &encode(&key))["code"], "issuer_key_set");
  let mut two = zkp.clone();
  two.issuer_key_set.push(two.issuer_key_set[0].clone());
  assert_eq!(verify(&verifier, &req, &encode(&two))["code"], "issuer_key_set");
  let mut system = zkp.clone();
  system.system_id = "urn:circuits:sha256:b457ba5382eb7604ef035e790f2cb24f0cd5fdcd065f383ff1c2c49fab1bb4df".into();
  assert_eq!(verify(&verifier, &req, &encode(&system))["code"], "scheme");

  // A request that does not offer the scheme.
  let mut no = req.clone();
  no["client_metadata"]["vp_formats_supported"]["zkp_req"]["system_id_values"] = json!(["urn:other"]);
  assert_eq!(prove(&prover, &no).unwrap_err().error, "unsupported_circuit");
  assert_eq!(verify(&verifier, &no, pres)["code"], "scheme");
  // An unknown function.
  let mut bad = req.clone();
  bad["dcql_query"]["credentials"][0]["_req"][0]["fn_id"] = json!("pseudonym-v1-sha256");
  assert_eq!(prove(&prover, &bad).unwrap_err().error, "unsupported_function");
  // The mdoc PRF, another version, an mdoc query.
  let mut prf = req.clone();
  prf["dcql_query"]["credentials"][0]["_req"][0]["params"]["prf"] = json!("sha-256");
  assert_eq!(prove(&prover, &prf).unwrap_err().error, "unsupported_config");
  let mut ver = req.clone();
  ver["dcql_query"]["credentials"][0]["_req"][0]["params"]["ver"] = json!(2);
  assert_eq!(prove(&prover, &ver).unwrap_err().error, "unsupported_request");
  let mut mdoc = req.clone();
  mdoc["dcql_query"]["credentials"][0]["meta"] = json!({ "source_format": "mso_mdoc", "doctype_value": "eu.europa.ec.eudi.nym_auth.1" });
  assert_eq!(prove(&prover, &mdoc).unwrap_err().error, "unsupported_request");
}

/// The /tech thread switch: a presentation made on every core verifies on one thread, and the
/// other way round; the metrics report the thread count.
#[test]
fn parallel_and_sequential_agree() {
  let prover = Prover::load();
  let verifier = Verifier::load(&std::fs::read(root("native/bbs/demo/issuer-params.bin")).unwrap()).unwrap();
  let req = request("community.example", "0123456789abcdef0123456789abcdef", Some(json!({ "ge": "2008-10-20", "le": "2013-10-19" })));
  let w = wallet();
  let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
  for (prove_parallel, verify_parallel) in [(true, false), (false, true)] {
    let input: ProveInput = serde_json::from_value(json!({
      "request": req, "credential_query_id": "nym_attestation_bbs", "handover": handover(&req),
      "credential": w["holders"][0]["credential"], "device_key": w["holders"][0]["device_key"], "parallel": prove_parallel,
    }))
    .unwrap();
    let out = prover.prove(&input).expect("prove");
    assert_eq!(out["metrics"]["threads"], if prove_parallel { cores } else { 1 });
    let v: VerifyInput = serde_json::from_value(json!({
      "request": req, "credential_query_id": "nym_attestation_bbs", "presentation": out["presentation"], "handover": handover(&req),
      "parallel": verify_parallel,
    }))
    .unwrap();
    let r = verifier.verify(&v);
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["metrics"]["threads"], if verify_parallel { cores } else { 1 });
  }
}

/// /tech's Trust new issuers: a credential from another BBS issuer is refused, its key named in the
/// refusal; with that key in `learned_issuers` it verifies (with the profile's schema). Reads
/// `scripts/fixtures/other-issuer-wallet-bbs.json`.
#[test]
fn learned_issuer() {
  use base64::Engine;
  let prover = Prover::load();
  let verifier = Verifier::load(&std::fs::read(root("native/bbs/demo/issuer-params.bin")).unwrap()).unwrap();
  let other: Value = serde_json::from_str(&std::fs::read_to_string(root("scripts/fixtures/other-issuer-wallet-bbs.json")).unwrap()).unwrap();
  let req = request("community.example", "learned-issuer-nonce-0123456789", None);
  let input: ProveInput = serde_json::from_value(json!({
    "request": req, "credential_query_id": "nym_attestation_bbs", "handover": handover(&req),
    "credential": other["holders"][0]["credential"], "device_key": other["holders"][0]["device_key"],
  }))
  .unwrap();
  let out = prover.prove(&input).unwrap();
  let pres = out["presentation"].as_str().unwrap();
  let with = |learned: Value| {
    let input: VerifyInput = serde_json::from_value(json!({
      "request": req, "credential_query_id": "nym_attestation_bbs", "presentation": pres, "handover": handover(&req), "learned_issuers": learned,
    }))
    .unwrap();
    verifier.verify(&input)
  };
  let refused = with(json!([]));
  assert_eq!(refused["code"], "issuer_key_set");
  let key = refused["issuer_key"].as_str().expect("the refusal names the key").to_string();
  let bytes = base64::engine::general_purpose::STANDARD.decode(&key).unwrap();
  assert_eq!(bytes.len(), 96);
  // Not a G2 point: still refused.
  let junk = base64::engine::general_purpose::STANDARD.encode([7u8; 96]);
  assert_eq!(with(json!([junk]))["code"], "issuer_key_set");
  let ok = with(json!([key]));
  assert_eq!(ok["ok"], true, "{ok}");
  // The demo issuer's presentations still verify with a learned key around.
  let demo = prove(&prover, &req).unwrap();
  assert_eq!(verify(&verifier, &req, demo["presentation"].as_str().unwrap())["ok"], true);
}


/// `prove_with`: the device key signs through a `HashSigner` the wallet supplies (a key-store key in
/// a real wallet; here the same software key, counting its signatures). The presentation verifies,
/// with the pseudonym `prove` gives, and the key signed exactly once.
#[test]
fn prove_with_a_device_signer() {
  use cd_ecdsa_pop::{HashSigner, Mode, SoftwareDevice};
  use nym_bbs::credential::CredentialJson;
  use nym_bbs::profile::{Handover, RequestObject};
  use nym_bbs::prover::PresentInput;
  use std::cell::Cell;

  struct Counting {
    device: SoftwareDevice,
    calls: Cell<u32>,
  }
  impl HashSigner for Counting {
    fn hash_public_key(&self) -> bbs_cd_plugin::error::Result<[u8; 33]> {
      self.device.hash_public_key()
    }
    fn sign_message(&self, msg: &[u8]) -> bbs_cd_plugin::error::Result<(p256::Scalar, p256::Scalar)> {
      self.calls.set(self.calls.get() + 1);
      self.device.sign_message(msg)
    }
  }

  let prover = Prover::load();
  let verifier = Verifier::load(&std::fs::read(root("native/bbs/demo/issuer-params.bin")).unwrap()).unwrap();
  let w = wallet();
  let d = nym_bbs::unb64url("d", w["holders"][0]["device_key"]["d"].as_str().unwrap()).unwrap();
  let signer = Counting {
    device: SoftwareDevice::from_key(p256::ecdsa::SigningKey::from_slice(&d).unwrap(), Mode::Hashed, false),
    calls: Cell::new(0),
  };

  let req = request("community.example", "fedcba9876543210fedcba9876543210", Some(json!({ "ge": "2008-10-20", "le": "2013-10-19" })));
  let ro: RequestObject = serde_json::from_value(req.clone()).unwrap();
  let handover_value: Handover = serde_json::from_value(handover(&req)).unwrap();
  let credential: CredentialJson = serde_json::from_value(w["holders"][0]["credential"].clone()).unwrap();
  let input = PresentInput {
    request: &ro,
    credential_query_id: "nym_attestation_bbs",
    handover: &handover_value,
    credential: &credential,
    parallel: false,
    threads: None,
    rulebook: nym_bbs::profile::Rulebook::V04,
  };
  let out = prover.prove_with(&input, &signer).expect("prove_with");
  assert_eq!(signer.calls.get(), 1);
  let v = verify(&verifier, &req, out["presentation"].as_str().unwrap());
  assert_eq!(v["ok"], true, "{v}");
  assert_eq!(out["results"]["nym"], v["results"]["nym"]);
  assert_eq!(out["results"]["nym"], prove(&prover, &req).unwrap()["results"]["nym"]);

  // A refusal comes before the device is asked: an unmet age range signs nothing.
  let adult_only = request("community.example", "fedcba9876543210fedcba9876543210", Some(json!({ "le": "2000-01-01" })));
  let ro2: RequestObject = serde_json::from_value(adult_only.clone()).unwrap();
  let handover_value: Handover = serde_json::from_value(handover(&adult_only)).unwrap();
  let input = PresentInput { request: &ro2, handover: &handover_value, ..input };
  assert_eq!(prover.prove_with(&input, &signer).unwrap_err().error, "unsatisfiable");
  assert_eq!(signer.calls.get(), 1);
}

/// Rulebook v0.5 (`docs/nym_auth_rulebook-v0.5.md`): age_check is an assertion with a `range` in
/// whole years; the presentation carries `proof_time`, and both sides compute the bounds from its
/// UTC date. The same credential and schema as v0.4.
#[test]
fn rulebook_v05_age_range() {
  use nym_bbs::dates::{AgeRange, Utc};
  use nym_bbs::presentation::Presentation;
  let prover = Prover::load();
  let verifier = Verifier::load(&std::fs::read(root("native/bbs/demo/issuer-params.bin")).unwrap()).unwrap();
  let w = wallet();
  let v05 = |range: &str, nonce: &str| {
    let mut req = request("community.example", nonce, Some(json!({})));
    let item = &mut req["dcql_query"]["credentials"][0]["_req"][1];
    *item = json!({ "fn_id": "age_check", "params": { "range": range } });
    req
  };
  let prove05 = |req: &Value| {
    let input: ProveInput = serde_json::from_value(json!({
      "request": req, "credential_query_id": "nym_attestation_bbs", "handover": handover(req),
      "credential": w["holders"][0]["credential"], "device_key": w["holders"][0]["device_key"], "rulebook": "0.5",
    }))
    .unwrap();
    prover.prove(&input)
  };
  let verify05 = |req: &Value, pres: &str, rulebook: &str, now: &str| {
    let input: VerifyInput = serde_json::from_value(json!({
      "request": req, "credential_query_id": "nym_attestation_bbs", "presentation": pres, "handover": handover(req),
      "rulebook": rulebook, "now": now, "proof_time_tolerance_s": 300,
    }))
    .unwrap();
    verifier.verify(&input)
  };
  let now = Utc::now().unwrap();
  let now_text = now.text();
  // The teen (born 2011-03-14) is 13 to 17 today, until 2029.
  let req = v05("13-17", "v05-age-range-nonce-0123456789ab");
  let out = prove05(&req).expect("prove v0.5");
  let pres = out["presentation"].as_str().unwrap();
  let decoded = Presentation::decode(&base64url(pres)).unwrap();
  let pt = decoded.proof_time.clone().expect("proof_time");
  assert_eq!(pt.len(), 20);
  assert!(decoded.results.iter().all(|(k, _)| k == "nym"), "an assertion has no output");
  let v = verify05(&req, pres, "0.5", &now_text);
  assert_eq!(v["ok"], true, "{v}");
  assert!(v["results"].get("age").is_none());
  let (ge, le) = AgeRange::parse("13-17").unwrap().bounds(Utc::parse_proof_time(&pt).unwrap().date()).unwrap();
  assert_eq!(v["bounds"]["ge"], json!(ge.as_ref().map(nym_bbs::dates::iso)));
  assert_eq!(v["bounds"]["le"], json!(le.as_ref().map(nym_bbs::dates::iso)));
  assert_eq!(out["statement"]["age_bounds"], v["bounds"]);

  // 18+: the teen cannot prove it.
  assert_eq!(prove05(&v05("18+", "v05-age-range-nonce-18plus-012345")).unwrap_err().error, "unsatisfiable");
  // The v0.5 request with a return handle on the assertion, or a range with A > B: unsupported.
  let mut with_return = req.clone();
  with_return["dcql_query"]["credentials"][0]["_req"][1]["return"] = json!("age");
  assert_eq!(prove05(&with_return).unwrap_err().error, "unsupported_request");
  assert_eq!(prove05(&v05("17-13", "v05-age-range-nonce-reversed-0123")).unwrap_err().error, "unsupported_request");

  // The verifier's clock: proof_time beyond the tolerance is refused.
  let late = Utc::from_unix(now.unix() + 3600).text();
  assert_eq!(verify05(&req, pres, "0.5", &late)["code"], "proof_time");
  // A v0.4 verifier refuses proof_time in a bbs_cd presentation.
  assert_eq!(verify05(&req, pres, "0.4", &now_text)["code"], "presentation");
  // Without proof_time, a v0.5 age check is refused.
  let mut bare = decoded.clone();
  bare.proof_time = None;
  let bare = b64(&bare.encode().unwrap());
  assert_eq!(verify05(&req, &bare, "0.5", &now_text)["code"], "proof_time");
  // Another proof_time within the tolerance but on another date would change the bounds; one on the
  // same date keeps them, and the proof still verifies only for the bounds it was made for.
  let mut moved = decoded.clone();
  moved.proof_time = Some(Utc::from_unix(Utc::parse_proof_time(&pt).unwrap().unix() - 1).text());
  let moved_pres = b64(&moved.encode().unwrap());
  let mv = verify05(&req, &moved_pres, "0.5", &now_text);
  let same_day = Utc::parse_proof_time(moved.proof_time.as_ref().unwrap()).unwrap().date() == Utc::parse_proof_time(&pt).unwrap().date();
  if same_day {
    assert_eq!(mv["ok"], true, "{mv}");
  }

  // v0.5 without an age check: no proof_time, the same as v0.4.
  let plain = request("community.example", "v05-plain-nonce-0123456789abcdef", None);
  let out = prove05(&plain).expect("prove v0.5 pseudonym only");
  let decoded = Presentation::decode(&base64url(out["presentation"].as_str().unwrap())).unwrap();
  assert!(decoded.proof_time.is_none());
  assert_eq!(verify05(&plain, out["presentation"].as_str().unwrap(), "0.5", &now_text)["ok"], true);
}

fn base64url(s: &str) -> Vec<u8> {
  use base64::Engine;
  base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap()
}

fn b64(b: &[u8]) -> String {
  use base64::Engine;
  base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
