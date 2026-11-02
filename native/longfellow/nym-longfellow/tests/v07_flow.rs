//! Rulebook v0.7 through the addon's own entry points: `Prover::sign`, `witness`, `prove` and
//! `Verifier::verify` with `rulebook: "0.7"` and the v0.7 circuits' system_id, on the package's
//! synthetic holders C and E (TEST ONLY: v0.7 layout, valid 2020–2099 and 2026–2027, signed with the
//! rulebook vectors' TEST Document Signer, which the verifier takes as a learned issuer; E's device
//! key has an odd y, so its credential's sign is `true`), and the version binding: each circuit set
//! answers only under its own rulebook version.
//! SHIPPED WITH THE CIRCUIT PACKAGE nym-auth-longfellow-v07-v1: drop into
//! `native/longfellow/nym-longfellow/tests/`. The demo holders' flow comes with their v0.7
//! credentials (VERIFIER-AGENT.md §4).

use nym_longfellow::circuit::DOC_TYPE;
use nym_longfellow::prover::{Prover, SignInput, WitnessInput};
use nym_longfellow::verifier::{Verifier, VerifyInput};
use nym_longfellow::{b64url, dates, decoy, hex, sha256, unhex, v07};
use serde_json::{Value, json};

fn here(p: &str) -> std::path::PathBuf {
  std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(p)
}

fn json_file(p: std::path::PathBuf) -> Value {
  serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))).unwrap()
}

const THUMBPRINT: [u8; 32] = [0x5a; 32];
const BSC_ID: &str = "urn:circuits:sha256:f4d75ee2a112c63adfb00f1da45347c4691085c8cca6ab13cee7b03f00cdbd52";
const V07_ID: &str = "urn:circuits:sha256:218a72dea317cfcde2e715860e6b3a5dda2c67260f4cf9e8311c62ef900c34bd";

fn request(nonce: &str, range: Option<&str>, ids: &[&str]) -> Value {
  request_prf(nonce, range, ids, "aes-128")
}

fn request_prf(nonce: &str, range: Option<&str>, ids: &[&str], prf: &str) -> Value {
  let mut req = vec![json!({ "fn_id": "pseudonym", "return": "nym", "params": { "config": "known-offender-matching-ssc", "ver": 1, "prf": prf } })];
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

/// Holder C (the vectors' device key) or E (its own device key, y odd) of the package's synthetic
/// holders, with the device key as a JWK.
fn holder(name: &str) -> Holder {
  use p256::elliptic_curve::sec1::ToEncodedPoint;
  let data = here("nym-auth-zk-v07/tests/data");
  let c = &json_file(data.join("v07_synthetic_holders.json"))["holders"][name];
  let d: [u8; 32] = match c["device_d"].as_str() {
    Some(dh) => unhex("device_d", dh).unwrap(),
    None => unhex("d", json_file(data.join("v07_test_vectors.json"))["keys"]["device"]["d"].as_str().unwrap()).unwrap(),
  };
  let sk = p256::SecretKey::from_slice(&d).unwrap();
  let pt = sk.public_key().to_encoded_point(false);
  Holder {
    issuer_signed: from_hex(c["issuer_signed"].as_str().unwrap()),
    secret_seed: c["secret_seed"].as_str().unwrap().into(),
    birth_date: c["birth_date"].as_str().unwrap().into(),
    device_key: json!({ "kty": "EC", "crv": "P-256", "x": b64url(pt.x().unwrap()), "y": b64url(pt.y().unwrap()), "d": b64url(&d) }),
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
fn v07_proves_and_verifies_and_binds_the_version() {
  let dir = here("circuits/mdoc");
  let prover = Prover::load(&dir).unwrap();
  let pem = std::fs::read_to_string(here("../vega/demo/document-signer.pem")).unwrap();
  let verifier = Verifier::load(&dir, &pem, 300).unwrap();
  let v7 = v07::system_id();
  assert_eq!(v7, V07_ID);
  let v6 = decoy::system_id();

  // info lists the four sets, each with its rulebook version.
  let info = prover.info();
  let listed: Vec<(String, String)> = info["circuits"]
    .as_array()
    .unwrap()
    .iter()
    .map(|c| (c["system_id"].as_str().unwrap().into(), c["rulebook"].as_str().unwrap().into()))
    .collect();
  assert!(listed.contains(&(v7.clone(), "0.7".into())), "{listed:?}");
  assert!(listed.contains(&(v6.clone(), "0.6".into())), "{listed:?}");
  assert!(listed.contains(&(BSC_ID.into(), "0.5".into())), "{listed:?}");
  assert_eq!(verifier.info()["circuits"], info["circuits"]);

  let learned = {
    use base64::Engine;
    let c = v07::credential(&holder("C").issuer_signed).unwrap();
    vec![base64::engine::general_purpose::STANDARD.encode(&c.document_signer)]
  };

  // Accepted under 0.7, with and without an age check, on one thread and on the pool, for C
  // (even y) and E (odd y).
  for (name, range, parallel) in [("C", None, false), ("C", Some("18+"), true), ("E", Some("18+"), false)] {
    let h = holder(name);
    let req = request("v07-accept-0123456789abcdef0123456", range, &[&v7]);
    let mut input = witness_input(&h, &req, &v7, "0.7", &sign(&prover, &h, &req));
    input.parallel = parallel;
    let w = prover.witness(&input).unwrap_or_else(|e| panic!("{name} {range:?}: {e:?}"));
    assert_eq!(w.summary["public_inputs"][1]["name"], "pseudonym.nym_block");
    let out = prover.prove(w).unwrap();
    assert_eq!(out["system_id"], v7.as_str());
    assert_eq!(out["metrics"]["proof_parts"][0]["bytes"], 64);
    let pres = out["presentation"].as_str().unwrap();
    let v = verify(&verifier, &req, pres, "0.7", &learned);
    assert_eq!(v["ok"], true, "{name} {range:?}: {v}");
    let seed: [u8; 16] = unhex("seed", &h.secret_seed).unwrap();
    let nb = nym_auth_zk_v07::witness::nym_block(&sha256(b"x509_san_dns:community.example"));
    assert_eq!(v["results"]["nym"].as_str().unwrap(), hex(&nym_auth_zk_v07::witness::pseudonym(&seed, &nb)));

    // The same presentation under 0.6: the v0.7 circuits are not a v0.6 circuit.
    let v = verify(&verifier, &req, pres, "0.6", &learned);
    assert_eq!(v["code"], "circuit", "{v}");
    // Without the learned issuer: the TEST Document Signer is not a demo trust anchor.
    let v = verify(&verifier, &req, pres, "0.7", &[]);
    assert_eq!(v["code"], "issuer_key_set", "{v}");
  }

  // The prover: the v0.7 id under 0.6, and the decoy id under 0.7, are refused before any work.
  let h = holder("C");
  let req = request("v07-refuse-0123456789abcdef01234567", None, &[&v7, &v6]);
  let sig = sign(&prover, &h, &req);
  let e = prover.witness(&witness_input(&h, &req, &v7, "0.6", &sig)).err().expect("v0.7 id under 0.6");
  assert_eq!(e.error, "unsupported_circuit", "{e:?}");
  let e = prover.witness(&witness_input(&h, &req, &v6, "0.7", &sig)).err().expect("decoy id under 0.7");
  assert_eq!(e.error, "unsupported_circuit", "{e:?}");

  // A v0.6 (decoy) credential with the v0.7 id: refused by the strict layout parse.
  let decoy_c = json_file(here("nym-auth-zk-decoy/tests/data/decoy_synthetic_holders.json"))["holders"]["C"]["issuer_signed"].as_str().unwrap().to_string();
  let hd = Holder { issuer_signed: from_hex(&decoy_c), ..holder("C") };
  let e = prover.witness(&witness_input(&hd, &req, &v7, "0.7", &sig)).err().expect("v0.6 credential");
  assert_eq!(e.error, "bad_credential", "{e:?}");

  // The pseudonym's prf: sha-256 under 0.7 is not what these circuits implement.
  let req = request_prf("v07-prf-0123456789abcdef0123456789", None, &[&v7], "sha-256");
  let e = prover.witness(&witness_input(&h, &req, &v7, "0.7", &sign(&prover, &h, &req))).err().expect("sha-256 under 0.7");
  assert_eq!(e.error, "unsupported_config", "{e:?}");

  // A request that does not offer the v0.7 id.
  let req = request("v07-notoffered-0123456789abcdef0123", None, &[&v6]);
  let e = prover.witness(&witness_input(&h, &req, &v7, "0.7", &sign(&prover, &h, &req))).err().expect("not offered");
  assert_eq!(e.error, "unsupported_circuit", "{e:?}");
}

#[test]
fn rulebook_versions_parse_v07() {
  use nym_longfellow::request::Rulebook;
  assert_eq!(Rulebook::parse(Some("0.7")).unwrap(), Rulebook::V07);
  assert!(Rulebook::parse(Some("0.8")).is_err());
  assert!(Rulebook::V07.years_range());
  assert_eq!((Rulebook::V06.prf(), Rulebook::V07.prf()), ("sha-256", "aes-128"));
}
