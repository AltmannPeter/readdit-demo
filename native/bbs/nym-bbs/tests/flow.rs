//! End to end on the demo credential: prove, verify, and the refusals.
//! Reads `app/wallet/demo-wallet-bbs.json` and `native/bbs/demo/issuer-params.bin`.

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
  let mut req = vec![json!({ "id": "pseudonym-bbs-v1", "return": "nym", "params": { "config": "known-offender-matching-ssc", "verifier_id_type": "x509_san_dns" } })];
  if let Some(a) = age {
    req.push(json!({ "id": "age_check", "return": "age", "params": a }));
  }
  json!({
    "client_id": format!("x509_san_dns:{host}"),
    "nonce": nonce,
    "response_uri": format!("https://{host}/api/vp/response/s1"),
    "dcql_query": { "credentials": [{ "id": "nym_attestation_mms", "format": "mms_zk", "meta": { "schema_id_value": "eu.europa.ec.eudi.nym_auth.bbs.1" }, "req": req }] },
    "client_metadata": { "vp_formats_supported": { "mms_zk": { "proof_system_values": ["bbs-cd-plugins-v0.1"], "scheme_id_values": ["urn:mms:bbs-cd:nym_auth:v1"] } } },
  })
}

fn handover(req: &Value) -> Value {
  json!({ "client_id": req["client_id"], "nonce": req["nonce"], "response_uri": req["response_uri"], "jwk_thumbprint": null })
}

fn prove(p: &Prover, req: &Value) -> Result<Value, nym_bbs::error::Refusal> {
  let w = wallet();
  let input: ProveInput = serde_json::from_value(json!({
    "request": req, "credential_query_id": "nym_attestation_mms", "handover": handover(req),
    "credential": w["holders"][0]["credential"], "device_key": w["holders"][0]["device_key"],
  }))
  .unwrap();
  p.prove(&input)
}

fn verify(v: &Verifier, req: &Value, presentation: &str) -> Value {
  let input: VerifyInput = serde_json::from_value(json!({
    "request": req, "credential_query_id": "nym_attestation_mms", "presentation": presentation, "handover": handover(req),
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
  let req = request("readdit.example", "0123456789abcdef0123456789abcdef", Some(teen.clone()));
  let out = prove(&prover, &req).expect("prove");
  let pres = out["presentation"].as_str().unwrap();
  let v = verify(&verifier, &req, pres);
  assert_eq!(v["ok"], true, "{v}");
  assert_eq!(v["results"]["age"], true);
  let nym = v["results"]["nym"].as_str().unwrap().to_string();
  assert_eq!(nym.len(), 64);
  assert_eq!(out["results"]["nym"], v["results"]["nym"]);

  // The same pseudonym in a new request to the same site, without age.
  let req2 = request("readdit.example", "fedcba9876543210fedcba9876543210", None);
  let out2 = prove(&prover, &req2).expect("prove");
  let v2 = verify(&verifier, &req2, out2["presentation"].as_str().unwrap());
  assert_eq!(v2["ok"], true, "{v2}");
  assert_eq!(v2["results"]["nym"].as_str().unwrap(), nym);
  assert!(v2["results"].get("age").is_none());

  // Another verifier identity, another pseudonym.
  let req3 = request("france.readdit.example", "fedcba9876543210fedcba9876543210", None);
  let out3 = prove(&prover, &req3).expect("prove");
  let v3 = verify(&verifier, &req3, out3["presentation"].as_str().unwrap());
  assert_eq!(v3["ok"], true, "{v3}");
  assert_ne!(v3["results"]["nym"].as_str().unwrap(), nym);

  // 18+: the teen cannot.
  let adult = request("readdit.example", "0123456789abcdef0123456789abcdef", Some(json!({ "le": "2008-10-19" })));
  assert_eq!(prove(&prover, &adult).unwrap_err().error, "unsatisfiable");

  // The presentation against another nonce, another response_uri, another site: refused.
  let mut other = req.clone();
  other["nonce"] = json!("ffffffffffffffffffffffffffffffff");
  assert_eq!(verify(&verifier, &other, pres)["code"], "proof_invalid");
  let mut other = req.clone();
  other["response_uri"] = json!("https://readdit.example/api/vp/response/s2");
  assert_eq!(verify(&verifier, &other, pres)["code"], "proof_invalid");
  let other = request("france.readdit.example", "0123456789abcdef0123456789abcdef", Some(teen.clone()));
  assert_eq!(verify(&verifier, &other, pres)["code"], "proof_invalid");
  // Against the same request without the age check (fewer plugins): refused.
  let fewer = request("readdit.example", "0123456789abcdef0123456789abcdef", None);
  assert_ne!(verify(&verifier, &fewer, pres)["ok"], true);

  // A flipped byte anywhere in the envelope.
  let mut bytes = nym_bbs::unb64url("p", pres).unwrap();
  for at in [10, bytes.len() / 2, bytes.len() - 5] {
    bytes[at] ^= 1;
    let v = verify(&verifier, &req, &nym_bbs::b64url(&bytes));
    assert_ne!(v["ok"], true, "flip at {at}");
    bytes[at] ^= 1;
  }
  assert_eq!(verify(&verifier, &req, "!!")["code"], "presentation");

  // A request that does not offer the scheme.
  let mut no = req.clone();
  no["client_metadata"]["vp_formats_supported"]["mms_zk"]["scheme_id_values"] = json!(["urn:other"]);
  assert_eq!(prove(&prover, &no).unwrap_err().error, "unsupported_circuit");
  assert_eq!(verify(&verifier, &no, pres)["code"], "scheme");
  // An unknown function.
  let mut bad = req.clone();
  bad["dcql_query"]["credentials"][0]["req"][0]["id"] = json!("pseudonym-v1-sha256");
  assert_eq!(prove(&prover, &bad).unwrap_err().error, "unsupported_function");
}
