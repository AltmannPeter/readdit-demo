//! `/tech`'s multithreading switch on the rulebook v0.5 circuits (`nym-auth-zk` 0.3.0): the same
//! verdicts at one thread and at every core. The golden presentations verify both ways; each demo
//! holder's presentation, proved on every core, verifies both ways and reports the threads it ran
//! on; a flipped proof byte is refused the same way both ways.

use nym_auth_zk as v5;
use nym_longfellow::circuit::DOC_TYPE;
use nym_longfellow::presentation::Presentation;
use nym_longfellow::prover::{Prover, SignInput, WitnessInput};
use nym_longfellow::verifier::{Verifier, VerifyInput};
use nym_longfellow::{b64url, dates, threads, unb64url};
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

fn verify(v: &Verifier, req: &Value, presentation: &str, parallel: bool) -> Value {
  let input: VerifyInput = serde_json::from_value(json!({
    "request": req, "credential_query_id": "nym_attestation", "presentation": presentation, "handover": handover(req),
    "now": dates::now().unwrap().text(), "rulebook": "0.5", "parallel": parallel,
  }))
  .unwrap();
  v.verify(&input)
}

/// A golden file's request and presentation, as `nym-auth-zk`'s tests read them.
fn golden(g: &Value) -> (v5::Request, v5::Presentation) {
  let hex = |s: &str| ::hex::decode(s).unwrap();
  let arr = |s: &str| -> [u8; 32] { hex(s).try_into().unwrap() };
  let r = &g["request"];
  let st = |v: &Value| v.as_str().unwrap().to_string();
  let se = &r["session"];
  let t = se["jwk_thumbprint"].as_str().map(arr);
  let session = match se["type"].as_str().unwrap() {
    "redirect" => v5::Session::Redirect { client_id: st(&se["client_id"]), nonce: st(&se["nonce"]), jwk_thumbprint: t, response_uri: st(&se["response_uri"]) },
    _ => v5::Session::DcApi { origin: st(&se["origin"]), nonce: st(&se["nonce"]), jwk_thumbprint: t },
  };
  let request = v5::Request {
    issuer_key: (arr(&st(&r["issuer_key"]["x"])), arr(&st(&r["issuer_key"]["y"]))),
    proof_time: st(&r["proof_time"]),
    age_range: r["age_range"].as_str().map(|a| v5::AgeRange::parse(a).unwrap()),
    verifier_id: st(&r["verifier_id"]),
    session,
  };
  let p = &g["presentation"];
  (request, v5::Presentation { pseudonym: arr(&st(&p["pseudonym"])), proof: hex(&st(&p["proof"])) })
}

#[test]
fn golden_presentations_verify_on_one_thread_and_on_every_core() {
  let v = v5::Verifier::load().unwrap();
  let dir = here("nym-auth-zk/tests/golden");
  let mut n = 0;
  for e in std::fs::read_dir(&dir).unwrap() {
    let g = json_file(e.unwrap().path());
    let (request, mut p) = golden(&g);
    for parallel in [false, true] {
      let (ok, threads) = threads::pool(parallel).install(|| (v.verify(&request, &p), v5::threads()));
      assert_eq!(ok, Ok(()));
      assert_eq!(threads, if parallel { threads::cores() } else { 1 });
    }
    let at = p.proof.len() / 3;
    p.proof[at] ^= 1;
    let refused: Vec<_> = [false, true].iter().map(|&par| threads::pool(par).install(|| v.verify(&request, &p))).collect();
    assert!(refused[0].is_err());
    assert_eq!(refused[0], refused[1]);
    n += 1;
  }
  assert_eq!(n, 3);
}

#[test]
fn demo_holders_prove_on_every_core_and_verify_both_ways() {
  let dir = here("circuits/mdoc");
  let prover = Prover::load(&dir).unwrap();
  let pem = std::fs::read_to_string(root("native/vega/demo/document-signer.pem")).unwrap();
  let verifier = Verifier::load(&dir, &pem, 300).unwrap();
  let wallet = json_file(root("app/wallet/demo-wallet.json"));
  for (k, h) in wallet["holders"].as_array().unwrap().iter().enumerate() {
    let req = request(&format!("threads-{k}-0123456789abcdef0123456789"));
    let sign: SignInput = serde_json::from_value(json!({ "device_key": h["device_key"], "doc_type": DOC_TYPE, "handover": handover(&req) })).unwrap();
    let signed = prover.sign(&sign).unwrap();
    let input: WitnessInput = serde_json::from_value(json!({
      "system_id": V05, "credential_query_id": "nym_attestation", "request": req, "handover": handover(&req),
      "credential": h["v05"]["credential"], "secret_seed": h["secret_seed"], "birth_date": h["v05"]["birth_date"],
      "device_signature": signed.device_signature, "rulebook": "0.5", "parallel": true,
    }))
    .unwrap();
    let w = prover.witness(&input).unwrap();
    assert_eq!(w.summary["metrics"]["threads"], threads::cores());
    let out = prover.prove(w).unwrap();
    assert_eq!(out["metrics"]["threads"], threads::cores());
    let pres = out["presentation"].as_str().unwrap();
    for parallel in [false, true] {
      let v = verify(&verifier, &req, pres, parallel);
      assert_eq!(v["ok"], true, "{v}");
      assert_eq!(v["metrics"]["threads"], if parallel { threads::cores() } else { 1 });
    }
    // A flipped proof byte: the same refusal both ways.
    let mut p = Presentation::decode(&unb64url("p", pres).unwrap()).unwrap();
    let at = p.proof.len() / 2;
    p.proof[at] ^= 1;
    let tampered = b64url(&p.encode().unwrap());
    let (a, b) = (verify(&verifier, &req, &tampered, false), verify(&verifier, &req, &tampered, true));
    assert_eq!(a["ok"], false);
    assert_eq!((&a["code"], &a["input"]), (&b["code"], &b["input"]), "{a} {b}");
  }
}
