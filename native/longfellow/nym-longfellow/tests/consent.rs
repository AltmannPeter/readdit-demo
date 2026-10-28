//! A wallet's order on the rulebook v0.5 circuits: the witness step (prebuild) during consent,
//! without the device signature; the signature after, through `WitnessData::attach_signature`;
//! then the prove step. The presentation verifies as the signature-first one does, with the same
//! pseudonym; a signature over another session or none at all is refused.

use nym_longfellow::circuit::DOC_TYPE;
use nym_longfellow::prover::{Prover, SignInput, WitnessInput};
use nym_longfellow::verifier::{Verifier, VerifyInput};
use nym_longfellow::{b64url, dates};
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

const V05: &str = "urn:circuits:sha256:f4d75ee2a112c63adfb00f1da45347c4691085c8cca6ab13cee7b03f00cdbd52";

fn request(nonce: &str) -> Value {
  json!({
    "client_id": "x509_san_dns:community.example",
    "nonce": nonce,
    "response_uri": "https://community.example/api/vp/response/s1",
    "dcql_query": { "credentials": [{ "id": "nym_attestation", "format": "zkp_req", "meta": { "source_format": "mso_mdoc", "doctype_value": DOC_TYPE },
      "_req": [{ "fn_id": "pseudonym", "return": "nym", "params": { "config": "known-offender-matching-ssc", "ver": 1, "prf": "sha-256" } }] }] },
    "client_metadata": { "vp_formats_supported": { "zkp_req": { "system_id_values": [V05], "proof_system_values": ["longfellow-libzk-v1"] } } },
  })
}

fn handover(req: &Value) -> Value {
  json!({ "client_id": req["client_id"], "nonce": req["nonce"], "response_uri": req["response_uri"], "jwk_thumbprint": b64url(&[0x5a; 32]) })
}

fn input(h: &Value, req: &Value, device_signature: &str) -> WitnessInput {
  serde_json::from_value(json!({
    "system_id": V05, "credential_query_id": "nym_attestation", "request": req, "handover": handover(req),
    "credential": h["v05"]["credential"], "secret_seed": h["secret_seed"], "birth_date": h["v05"]["birth_date"],
    "device_signature": device_signature, "rulebook": "0.5",
  }))
  .unwrap()
}

#[test]
fn prebuild_before_the_signature_proves_the_same() {
  let dir = here("circuits/mdoc");
  let prover = Prover::load(&dir).unwrap();
  let pem = std::fs::read_to_string(root("native/vega/demo/document-signer.pem")).unwrap();
  let verifier = Verifier::load(&dir, &pem, 300).unwrap();
  let wallet = json_file(root("app/wallet/demo-wallet.json"));
  for (k, h) in wallet["holders"].as_array().unwrap().iter().enumerate() {
    let req = request(&format!("consent-{k}-0123456789abcdef0123456789"));
    let sign = |req: &Value| {
      let s: SignInput = serde_json::from_value(json!({ "device_key": h["device_key"], "doc_type": DOC_TYPE, "handover": handover(req) })).unwrap();
      prover.sign(&s).unwrap().device_signature
    };

    // Signature first, as the demo phone does.
    let first = prover.prove(prover.witness(&input(h, &req, &sign(&req))).unwrap()).unwrap();

    // Prebuild first, the signature after.
    let mut w = prover.witness(&input(h, &req, "")).unwrap();
    assert!(!w.signed());
    assert!(w.device_message().is_some());
    w.attach_signature(&sign(&req)).unwrap();
    assert!(w.signed());
    let later = prover.prove(w).unwrap();

    for out in [&first, &later] {
      let v: Value = verifier.verify(
        &serde_json::from_value::<VerifyInput>(json!({
          "request": req, "credential_query_id": "nym_attestation", "presentation": out["presentation"], "handover": handover(&req),
          "now": dates::now().unwrap().text(), "rulebook": "0.5",
        }))
        .unwrap(),
      );
      assert_eq!(v["ok"], true, "{v}");
    }
    assert_eq!(first["results"], later["results"], "the same pseudonym");
    assert!(later["metrics"]["prebuild_ms"].as_f64().is_some());

    // A signature over another session is refused when attached; without one, no proof.
    let other = request(&format!("other-{k}-0123456789abcdef0123456789abc"));
    let mut w = prover.witness(&input(h, &req, "")).unwrap();
    let e = w.attach_signature(&sign(&other)).unwrap_err();
    assert!(e.detail.contains("does not verify"), "{}", e.detail);
    assert!(!w.signed());
    assert!(prover.prove(w).unwrap_err().contains("missing"));
  }
}
