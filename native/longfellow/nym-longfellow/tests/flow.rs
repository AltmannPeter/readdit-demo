//! The archive's known answers, then end to end on Community's demo credentials.
//!
//! - `archive_witness_and_proof`: the witness of the archive's fixture (verifier 1, DC API
//!   handover) equals `circuits/mdoc/test/*.bin` slot for slot (SPEC.md L7, as `nymauth-lf
//!   check`), and the archive's `test/proof.bin` verifies, with the refusals of L9.
//! - `prove_verify_and_refusals`: the holder's three steps and the verifier on
//!   `app/wallet/demo-wallet.json` with the OpenID4VP B.2.6.1 handover Community uses.

use nym_longfellow::cbor::{NULL, bstr, tstr, write_head};
use nym_longfellow::circuit::DOC_TYPE;
use nym_longfellow::handover::challenge_digest;
use nym_longfellow::prover::{Prover, SignInput, WitnessInput};
use nym_longfellow::verifier::{Verifier, VerifyInput};
use nym_longfellow::witness::{self, Layout, Private, Public};
use nym_longfellow::x509::PublicKey;
use nym_longfellow::zk::{Circuits, Rejection, ZkVerifierPair};
use nym_longfellow::{b64url, mdoc, sha256, unhex};
use serde_json::{Value, json};

fn here(p: &str) -> std::path::PathBuf {
  std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(p)
}

fn root(p: &str) -> std::path::PathBuf {
  here(&format!("../../{p}"))
}

fn json_file(p: std::path::PathBuf) -> Value {
  serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

/// The archive's fixture inputs for verifier `v`, with its DC API SessionTranscript.
fn archive_inputs(v: usize) -> (Public, [u8; 16], [u8; 64], Vec<u8>, String) {
  let ver = json_file(here("fixtures/verifier.json"));
  let nym = json_file(here("fixtures/pseudonym.json"));
  let s = |x: &Value| x.as_str().unwrap().to_string();
  let (qx, qy) = s(&ver["issuer_key"]).split_once(',').map(|(a, b)| (a.to_string(), b.to_string())).unwrap();
  let vr = &nym["verifiers"][v];
  let info = [write_head(4, 3), tstr(&s(&vr["origin"])), tstr(&s(&vr["nonce"])), vec![NULL]].concat();
  let transcript =
    [write_head(4, 3), vec![NULL, NULL], write_head(4, 2), tstr("OpenID4VPDCAPIHandover"), bstr(&sha256(&info))].concat();
  let public = Public {
    time: s(&ver["mdoc"]["time"]),
    earliest: s(&ver["mdoc"]["earliest"]),
    cutoff: s(&ver["mdoc"]["cutoff"]),
    verifier_input: sha256(s(&vr["client_id"]).as_bytes()),
    issuer_key: PublicKey { x: unhex("Qx", &qx).unwrap(), y: unhex("Qy", &qy).unwrap() },
    challenge: challenge_digest(&transcript, DOC_TYPE),
  };
  assert_eq!(nym_longfellow::hex(&public.challenge), s(&vr["mdoc"]["challenge_digest"]));
  let seed = unhex("seed", &s(&nym["holder"]["secret_seed"])).unwrap();
  let dev = unhex("device_signature", &s(&vr["mdoc"]["device_signature"])).unwrap();
  (public, seed, dev, transcript, s(&vr["pseudonym"]))
}

#[test]
fn archive_witness_and_proof() {
  let dir = here("circuits/mdoc");
  let layout = Layout::read(&dir).unwrap();
  let (public, seed, dev, transcript, expected_nym) = archive_inputs(0);
  let credential = std::fs::read_to_string(here("fixtures/nym-auth-mdoc.txt")).unwrap();
  let m = mdoc::parse(credential.trim()).unwrap();
  let mut w = witness::witness(&layout, &public, &Private { mdoc: &m, secret_seed: seed, device_signature: dev }).unwrap();
  assert_eq!(nym_longfellow::hex(&w.nym), expected_nym);

  // L7: a_p,k = k + 1 and the fixture's a_v.
  let th = std::fs::read(dir.join("test/hash-witness.bin")).unwrap();
  let ts = std::fs::read(dir.join("test/sig-witness.bin")).unwrap();
  let npub = layout.hash.npub;
  let av = u128::from_le_bytes(th[16 * (npub - 3)..16 * (npub - 2)].try_into().unwrap());
  w.set_ap(&layout, std::array::from_fn(|k| (k + 1) as u128));
  w.set_av(&layout, av);
  let bad_h = w.h.iter().enumerate().filter(|(i, e)| e[..] != th[16 * i..16 * i + 16]).count();
  let bad_s = w.s.iter().enumerate().filter(|(i, e)| e[..] != ts[32 * i..32 * i + 32]).count();
  assert_eq!((w.h.len(), w.s.len()), (th.len() / 16, ts.len() / 32));
  assert_eq!((bad_h, bad_s), (0, 0));

  // L9: the archive's proof verifies; another pseudonym, another verifier's request and a flipped
  // byte are refused.
  let pair = ZkVerifierPair::new(Circuits::load(&dir).unwrap());
  let proof = std::fs::read(dir.join("test/proof.bin")).unwrap();
  let nym: [u8; 32] = unhex("nym", &expected_nym).unwrap();
  assert_eq!(pair.verify(&proof, &public, &nym, &transcript), Ok(()));
  let mut other = nym;
  other[0] ^= 1;
  assert_eq!(pair.verify(&proof, &public, &other, &transcript), Err(Rejection::Invalid("hash")));
  let (public2, _, _, transcript2, _) = archive_inputs(1);
  assert!(pair.verify(&proof, &public2, &nym, &transcript2).is_err());
  let mut flipped = proof.clone();
  flipped[proof.len() / 2] ^= 1;
  assert!(pair.verify(&flipped, &public, &nym, &transcript).is_err());
}

// ---- Community's flow ----

fn request(host: &str, nonce: &str, age: Option<Value>) -> Value {
  let mut req = vec![json!({ "fn_id": "pseudonym", "return": "nym", "params": { "config": "known-offender-matching-ssc", "ver": 1, "prf": "sha-256" } })];
  if let Some(a) = age {
    req.push(json!({ "fn_id": "age_check", "return": "age", "params": a }));
  }
  json!({
    "client_id": format!("x509_san_dns:{host}"),
    "nonce": nonce,
    "response_uri": format!("https://{host}/api/vp/response/s1"),
    "dcql_query": { "credentials": [{ "id": "nym_attestation", "format": "zkp_req", "meta": { "source_format": "mso_mdoc", "doctype_value": DOC_TYPE }, "_req": req }] },
    "client_metadata": { "vp_formats_supported": { "zkp_req": {
      "system_id_values": ["urn:circuits:vega:nym_auth:v1", "urn:circuits:longfellow:nym_auth:v1"],
      "proof_system_values": ["vega-v1", "longfellow-libzk-v1"] } } },
  })
}

fn handover(req: &Value) -> Value {
  json!({ "client_id": req["client_id"], "nonce": req["nonce"], "response_uri": req["response_uri"], "jwk_thumbprint": null })
}

fn present(p: &Prover, holder: &Value, req: &Value) -> Result<Value, nym_longfellow::error::Refusal> {
  let sign: SignInput =
    serde_json::from_value(json!({ "device_key": holder["device_key"], "doc_type": DOC_TYPE, "handover": handover(req) })).unwrap();
  let signed = p.sign(&sign)?;
  let input: WitnessInput = serde_json::from_value(json!({
    "system_id": "urn:circuits:longfellow:nym_auth:v1", "credential_query_id": "nym_attestation",
    "request": req, "handover": handover(req), "credential": holder["credential"],
    "secret_seed": holder["secret_seed"], "device_signature": signed.device_signature,
  }))
  .unwrap();
  let w = p.witness(&input)?;
  Ok(p.prove(w).unwrap())
}

fn verify(v: &Verifier, req: &Value, presentation: &str, now: &str) -> Value {
  let input: VerifyInput = serde_json::from_value(json!({
    "request": req, "credential_query_id": "nym_attestation", "presentation": presentation, "handover": handover(req), "now": now,
  }))
  .unwrap();
  v.verify(&input)
}

fn now() -> String {
  let t = nym_longfellow::dates::now().unwrap();
  t.text()
}

#[test]
fn prove_verify_and_refusals() {
  let dir = here("circuits/mdoc");
  let prover = Prover::load(&dir).unwrap();
  let pem = std::fs::read_to_string(root("native/vega/demo/document-signer.pem")).unwrap();
  let verifier = Verifier::load(&dir, &pem, 300).unwrap();
  let wallet = json_file(root("app/wallet/demo-wallet.json"));
  let holders = wallet["holders"].as_array().unwrap();
  let birth = |h: &Value| mdoc::parse(h["credential"]["issuer_signed"].as_str().unwrap()).unwrap().birth_date;
  let teen = holders.iter().find(|h| birth(h).year >= 2009).expect("a teen");
  let adult = holders.iter().find(|h| birth(h).year < 2000).expect("an adult");

  // 13 to 17 inclusive, today: born after today − 18 years and on or before today − 13 years.
  let t = nym_longfellow::dates::now().unwrap().date;
  let d = |y: u32| nym_longfellow::dates::Date { year: t.year - y, ..t };
  let next = |x: nym_longfellow::dates::Date| {
    let u = nym_longfellow::dates::unix(&nym_longfellow::dates::Time { date: x, hour: 0, minute: 0, second: 0 }) + 86_400;
    nym_longfellow::dates::from_unix(u).unwrap().date
  };
  let range = json!({ "ge": next(d(18)).text(), "le": d(13).text() });

  let req = request("community.example", "0123456789abcdef0123456789abcdef", Some(range.clone()));
  let out = present(&prover, teen, &req).expect("teen proves 13-17");
  let pres = out["presentation"].as_str().unwrap();
  let v = verify(&verifier, &req, pres, &now());
  assert_eq!(v["ok"], true, "{v}");
  assert_eq!(v["results"]["age"], true);
  let nym = v["results"]["nym"].as_str().unwrap().to_string();
  let seed: [u8; 16] = unhex("seed", teen["secret_seed"].as_str().unwrap()).unwrap();
  assert_eq!(nym, nym_longfellow::hex(&witness::pseudonym(&seed, &sha256(b"x509_san_dns:community.example"))));
  println!("presentation {} bytes, metrics {}", pres.len() * 3 / 4, out["metrics"]);

  // Refusals: another verifier's request, a moved proof_time, another pseudonym, a changed bound.
  let other = request("other.example", "0123456789abcdef0123456789abcdef", Some(range.clone()));
  assert_eq!(verify(&verifier, &other, pres, &now())["code"], "proof_invalid");
  let later = nym_longfellow::dates::from_unix(nym_longfellow::dates::unix(&nym_longfellow::dates::now().unwrap()) + 3600).unwrap();
  assert_eq!(verify(&verifier, &req, pres, &later.text())["code"], "proof_time");
  let narrower = request("community.example", "0123456789abcdef0123456789abcdef", Some(json!({ "ge": next(d(17)).text(), "le": d(13).text() })));
  let r = verify(&verifier, &narrower, pres, &now());
  assert_eq!((r["code"].as_str(), r["input"].as_str()), (Some("proof_invalid"), Some("hash")), "{r}");
  let bytes = nym_longfellow::unb64url("p", pres).unwrap();
  let mut p = nym_longfellow::presentation::Presentation::decode(&bytes).unwrap();
  p.results[0].1 = nym_longfellow::presentation::ResultValue::Pseudonym([7; 32]);
  assert_eq!(verify(&verifier, &req, &b64url(&p.encode().unwrap()), &now())["code"], "proof_invalid");

  // The adult cannot prove 13 to 17; proves 18+.
  let refused = present(&prover, adult, &req).expect_err("adult refused");
  assert_eq!(refused.error, "unsatisfiable");
  let req18 = request("community.example", "fedcba9876543210fedcba9876543210", Some(json!({ "le": d(18).text() })));
  let out18 = present(&prover, adult, &req18).expect("adult proves 18+");
  assert_eq!(verify(&verifier, &req18, out18["presentation"].as_str().unwrap(), &now())["ok"], true);
  assert_eq!(present(&prover, teen, &req18).expect_err("teen refused").error, "unsatisfiable");

  // Sign-up without age: the same pseudonym as with it.
  let plain = request("community.example", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", None);
  let out2 = present(&prover, teen, &plain).unwrap();
  let v2 = verify(&verifier, &plain, out2["presentation"].as_str().unwrap(), &now());
  assert_eq!(v2["ok"], true, "{v2}");
  assert_eq!(v2["results"]["nym"].as_str().unwrap(), nym);
}

/// Rulebook v0.5's request side, on the v0.4 circuits and credential (the v0.5 circuits over bsc
/// and psc are not here yet): age_check is an assertion with a `range` in whole years, and the
/// prover and the verifier compute E and C from it and the UTC date of `proof_time`.
#[test]
fn rulebook_v05_request_side() {
  use nym_longfellow::dates::{AgeRange, range_bounds};
  let dir = here("circuits/mdoc");
  let prover = Prover::load(&dir).unwrap();
  let pem = std::fs::read_to_string(root("native/vega/demo/document-signer.pem")).unwrap();
  let verifier = Verifier::load(&dir, &pem, 300).unwrap();
  let wallet = json_file(root("app/wallet/demo-wallet.json"));
  let holders = wallet["holders"].as_array().unwrap();
  let birth = |h: &Value| mdoc::parse(h["credential"]["issuer_signed"].as_str().unwrap()).unwrap().birth_date;
  let teen = holders.iter().find(|h| birth(h).year >= 2009).expect("a teen");
  let v05 = |range: &str, nonce: &str| {
    let mut req = request("community.example", nonce, Some(json!({})));
    req["dcql_query"]["credentials"][0]["_req"][1] = json!({ "fn_id": "age_check", "params": { "range": range } });
    req
  };
  let present05 = |req: &Value| -> Result<Value, nym_longfellow::error::Refusal> {
    let sign: SignInput = serde_json::from_value(json!({ "device_key": teen["device_key"], "doc_type": DOC_TYPE, "handover": handover(req) })).unwrap();
    let signed = prover.sign(&sign)?;
    let input: WitnessInput = serde_json::from_value(json!({
      "system_id": "urn:circuits:longfellow:nym_auth:v1", "credential_query_id": "nym_attestation",
      "request": req, "handover": handover(req), "credential": teen["credential"],
      "secret_seed": teen["secret_seed"], "device_signature": signed.device_signature, "rulebook": "0.5",
    }))
    .unwrap();
    let w = prover.witness(&input)?;
    Ok(prover.prove(w).unwrap())
  };
  let verify05 = |req: &Value, pres: &str, rulebook: &str| {
    let input: VerifyInput = serde_json::from_value(json!({
      "request": req, "credential_query_id": "nym_attestation", "presentation": pres, "handover": handover(req), "now": now(), "rulebook": rulebook,
    }))
    .unwrap();
    verifier.verify(&input)
  };

  let req = v05("13-17", "v05-request-side-0123456789abcdef");
  let out = present05(&req).expect("the teen proves 13-17");
  let pres = out["presentation"].as_str().unwrap();
  let v = verify05(&req, pres, "0.5");
  assert_eq!(v["ok"], true, "{v}");
  assert!(v["results"].get("age").is_none(), "an assertion has no output");
  let pt = nym_longfellow::dates::now().unwrap().date;
  let (e, c) = range_bounds(&AgeRange::parse("13-17").unwrap(), &pt);
  assert_eq!(v["bounds"], json!({ "ge": e.map(|d| d.text()), "le": c.map(|d| d.text()) }));
  // Read as v0.4, the same request lacks the age check's return handle.
  assert_eq!(verify05(&req, pres, "0.4")["code"], "request");
  // 18+: the teen cannot prove it; a return handle on the assertion: unsupported.
  assert_eq!(present05(&v05("18+", "v05-request-side-18plus-012345678")).unwrap_err().error, "unsatisfiable");
  let mut with_return = req.clone();
  with_return["dcql_query"]["credentials"][0]["_req"][1]["return"] = json!("age");
  assert_eq!(present05(&with_return).unwrap_err().error, "unsupported_request");
}
