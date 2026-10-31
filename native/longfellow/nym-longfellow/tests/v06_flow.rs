//! Rulebook v0.6 through the addon's own entry points: `Prover::sign`, `witness`, `prove` and
//! `Verifier::verify` with `rulebook: "0.6"` and the decoy circuits' system_id, on the package's
//! synthetic holder C (TEST ONLY: decoy layout, valid 2020–2099, signed with the rulebook vectors'
//! TEST Document Signer, which the verifier takes as a learned issuer), and the version binding:
//! each circuit set answers only under its own rulebook version.
//! SHIPPED WITH THE CIRCUIT PACKAGE nym-auth-longfellow-decoy-v1 (rulebook v0.6 revision): drop into
//! `native/longfellow/nym-longfellow/tests/`. The demo holders' flow (`decoy_flow.rs`) comes with
//! their decoy credentials (VERIFIER-AGENT.md §4).

use nym_longfellow::circuit::DOC_TYPE;
use nym_longfellow::prover::{Prover, SignInput, WitnessInput};
use nym_longfellow::verifier::{Verifier, VerifyInput};
use nym_longfellow::{b64url, dates, decoy, hex, sha256, unhex};
use serde_json::{Value, json};

fn here(p: &str) -> std::path::PathBuf {
  std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(p)
}

fn json_file(p: std::path::PathBuf) -> Value {
  serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))).unwrap()
}

const THUMBPRINT: [u8; 32] = [0x5a; 32];
const BSC_ID: &str = "urn:circuits:sha256:f4d75ee2a112c63adfb00f1da45347c4691085c8cca6ab13cee7b03f00cdbd52";

fn request(nonce: &str, range: Option<&str>, ids: &[&str]) -> Value {
  let mut req = vec![json!({ "fn_id": "pseudonym", "return": "nym", "params": { "config": "known-offender-matching-ssc", "ver": 1, "prf": "sha-256" } })];
  if let Some(r) = range {
    req.push(json!({ "fn_id": "age_check", "params": { "range": r } }));
  }
  json!({
    "client_id": "x509_san_dns:community.example",
    "nonce": nonce,
    "response_uri": "https://community.example/api/vp/response/s1",
    "dcql_query": { "credentials": [{ "id": "nym_attestation", "format": "zkp_req", "meta": { "source_format": "mso_mdoc", "doctype_value": DOC_TYPE }, "_req": req }] },
    "client_metadata": { "vp_formats_supported": { "zkp_req": { "system_id_values": ids, "proof_system_values": ["longfellow-libzk-v1"] } } },
  })
}

fn handover(req: &Value) -> Value {
  json!({ "client_id": req["client_id"], "nonce": req["nonce"], "response_uri": req["response_uri"], "jwk_thumbprint": b64url(&THUMBPRINT) })
}

fn from_hex(h: &str) -> Vec<u8> {
  (0..h.len() / 2).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap()).collect()
}

struct Holder {
  issuer_signed: Vec<u8>,
  secret_seed: String,
  birth_date: String,
  device_key: Value,
}

/// Holder C of the package's synthetic holders, with the vectors' device key as a JWK.
fn holder_c() -> Holder {
  let data = here("nym-auth-zk-decoy/tests/data");
  let c = &json_file(data.join("decoy_synthetic_holders.json"))["holders"]["C"];
  let d = &json_file(data.join("decoy_test_vectors.json"))["keys"]["device"];
  let k = |n: &str| b64url(&unhex::<32>(n, d[n].as_str().unwrap()).unwrap());
  Holder {
    issuer_signed: from_hex(c["issuer_signed"].as_str().unwrap()),
    secret_seed: c["secret_seed"].as_str().unwrap().into(),
    birth_date: c["birth_date"].as_str().unwrap().into(),
    device_key: json!({ "kty": "EC", "crv": "P-256", "x": k("x"), "y": k("y"), "d": k("d") }),
  }
}

fn witness_input(h: &Holder, req: &Value, system_id: &str, rulebook: &str, device_signature: &str) -> WitnessInput {
  serde_json::from_value(json!({
    "system_id": system_id, "credential_query_id": "nym_attestation",
    "request": req, "handover": handover(req),
    "credential": { "format": "mso_mdoc", "doctype": DOC_TYPE, "rulebook": rulebook, "issuer_signed": b64url(&h.issuer_signed) },
    "secret_seed": h.secret_seed, "birth_date": h.birth_date, "device_signature": device_signature, "rulebook": rulebook,
  }))
  .unwrap()
}

fn sign(p: &Prover, h: &Holder, req: &Value) -> String {
  let input: SignInput = serde_json::from_value(json!({ "device_key": h.device_key, "doc_type": DOC_TYPE, "handover": handover(req) })).unwrap();
  p.sign(&input).unwrap().device_signature
}

fn verify(v: &Verifier, req: &Value, presentation: &str, rulebook: &str, learned: &[String]) -> Value {
  let input: VerifyInput = serde_json::from_value(json!({
    "request": req, "credential_query_id": "nym_attestation", "presentation": presentation, "handover": handover(req),
    "now": dates::now().unwrap().text(), "learned_issuers": learned, "rulebook": rulebook,
  }))
  .unwrap();
  v.verify(&input)
}

#[test]
fn v06_proves_and_verifies_and_binds_the_version() {
  let dir = here("circuits/mdoc");
  let prover = Prover::load(&dir).unwrap();
  let pem = std::fs::read_to_string(here("../vega/demo/document-signer.pem")).unwrap();
  let verifier = Verifier::load(&dir, &pem, 300).unwrap();
  let v6 = decoy::system_id();
  assert_eq!(v6, "urn:circuits:sha256:5d7d2b5d094032df5b02f576d2ae7b99d3f0932d47516336693f8d670cfd63ac");

  // info lists the three sets, each with its rulebook version.
  let info = prover.info();
  let listed: Vec<(String, String)> = info["circuits"]
    .as_array()
    .unwrap()
    .iter()
    .map(|c| (c["system_id"].as_str().unwrap().into(), c["rulebook"].as_str().unwrap().into()))
    .collect();
  assert!(listed.contains(&(v6.clone(), "0.6".into())), "{listed:?}");
  assert!(listed.contains(&(BSC_ID.into(), "0.5".into())), "{listed:?}");

  let h = holder_c();
  let c = decoy::credential(&h.issuer_signed).unwrap();
  use base64::Engine;
  let learned = vec![base64::engine::general_purpose::STANDARD.encode(&c.document_signer)];

  // Accepted under 0.6, with and without an age check, on one thread and on the pool.
  for (range, parallel) in [(None, false), (Some("18+"), true)] {
    let req = request("v06-accept-0123456789abcdef0123456", range, &[&v6]);
    let mut input = witness_input(&h, &req, &v6, "0.6", &sign(&prover, &h, &req));
    input.parallel = parallel;
    let w = prover.witness(&input).unwrap_or_else(|e| panic!("{range:?}: {e:?}"));
    let out = prover.prove(w).unwrap();
    assert_eq!(out["system_id"], v6.as_str());
    let pres = out["presentation"].as_str().unwrap();
    let v = verify(&verifier, &req, pres, "0.6", &learned);
    assert_eq!(v["ok"], true, "{range:?}: {v}");
    let seed: [u8; 16] = unhex("seed", &h.secret_seed).unwrap();
    assert_eq!(
      v["results"]["nym"].as_str().unwrap(),
      hex(&nym_auth_zk_decoy::witness::pseudonym(&seed, &sha256(b"x509_san_dns:community.example")))
    );

    // The same presentation under 0.5: the decoy circuits are not a v0.5 circuit.
    let v = verify(&verifier, &req, pres, "0.5", &learned);
    assert_eq!(v["code"], "circuit", "{v}");
    // Without the learned issuer: the TEST Document Signer is not a demo trust anchor.
    let v = verify(&verifier, &req, pres, "0.6", &[]);
    assert_eq!(v["code"], "issuer_key_set", "{v}");
  }

  // The prover: the decoy id under 0.5, and the bsc id under 0.6, are refused before any work.
  let req = request("v06-refuse-0123456789abcdef01234567", None, &[&v6, BSC_ID]);
  let sig = sign(&prover, &h, &req);
  let e = prover.witness(&witness_input(&h, &req, &v6, "0.5", &sig)).err().expect("decoy id under 0.5");
  assert_eq!(e.error, "unsupported_circuit", "{e:?}");
  let e = prover.witness(&witness_input(&h, &req, BSC_ID, "0.6", &sig)).err().expect("bsc id under 0.6");
  assert_eq!(e.error, "unsupported_circuit", "{e:?}");

  // A compact-profile (v0.5) credential with the decoy id: refused by the strict layout parse.
  let compact = std::fs::read(here("../../profiles/nym-auth-v0.5/test-vectors/nym_auth_mdoc/issuer_signed.cbor")).unwrap();
  let hc = Holder { issuer_signed: compact, ..holder_c() };
  let e = prover.witness(&witness_input(&hc, &req, &v6, "0.6", &sig)).err().expect("compact credential");
  assert_eq!(e.error, "bad_credential", "{e:?}");

  // A request that does not offer the decoy id.
  let req = request("v06-notoffered-0123456789abcdef0123", None, &[BSC_ID]);
  let e = prover.witness(&witness_input(&h, &req, &v6, "0.6", &sign(&prover, &h, &req))).err().expect("not offered");
  assert_eq!(e.error, "unsupported_circuit", "{e:?}");
}

#[test]
fn rulebook_versions_parse() {
  use nym_longfellow::request::Rulebook;
  assert_eq!(Rulebook::parse(None).unwrap(), Rulebook::V04);
  assert_eq!(Rulebook::parse(Some("0.5")).unwrap(), Rulebook::V05);
  assert_eq!(Rulebook::parse(Some("0.6")).unwrap(), Rulebook::V06);
  assert!(Rulebook::parse(Some("0.7")).is_err());
  assert!(!Rulebook::V04.years_range() && Rulebook::V05.years_range() && Rulebook::V06.years_range());
}
