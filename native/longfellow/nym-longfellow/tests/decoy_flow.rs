//! Rulebook v0.6 end to end on the `nym-auth-zk-decoy` circuits (the decoy-digest layout), through
//! the holder's three steps (`Prover::sign`, `witness`, `prove`) and `Verifier::verify` with
//! `rulebook: "0.6"`, on the demo holders' v0.6 credentials (`app/wallet/demo-wallet.json`, each
//! holder's `v06`, issued by nym-issuer --v06). The circuit package's VERIFIER-AGENT.md §4 lists the
//! cases. Also: every demo v0.6 credential passes the crate's strict layout parse, nym-issuer's copy
//! of the layout template is the crate's, and the site's registry entry (shared/registry/circuits.ts)
//! lists the adapter's public inputs with the same element counts.

use nym_auth_zk_decoy as v6;
use nym_longfellow::circuit::DOC_TYPE;
use nym_longfellow::presentation::{Presentation, ResultValue};
use nym_longfellow::prover::{Prover, SignInput, WitnessInput};
use nym_longfellow::verifier::{Verifier, VerifyInput};
use nym_longfellow::{b64url, dates, decoy, sha256, unb64url, x509};
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
const BSC_ID: &str = "urn:circuits:sha256:f4d75ee2a112c63adfb00f1da45347c4691085c8cca6ab13cee7b03f00cdbd52";
const DECOY_ID: &str = "urn:circuits:sha256:5d7d2b5d094032df5b02f576d2ae7b99d3f0932d47516336693f8d670cfd63ac";

fn request_for(host: &str, nonce: &str, range: Option<&str>, ids: &[&str]) -> Value {
  let mut req = vec![json!({ "fn_id": "pseudonym", "return": "nym", "params": { "config": "known-offender-matching-ssc", "ver": 1, "prf": "sha-256" } })];
  if let Some(r) = range {
    req.push(json!({ "fn_id": "age_check", "params": { "range": r } }));
  }
  json!({
    "client_id": format!("x509_san_dns:{host}"),
    "nonce": nonce,
    "response_uri": format!("https://{host}/api/vp/response/s1"),
    "dcql_query": { "credentials": [{ "id": "nym_attestation", "format": "zkp_req", "meta": { "source_format": "mso_mdoc", "doctype_value": DOC_TYPE }, "_req": req }] },
    "client_metadata": { "vp_formats_supported": { "zkp_req": { "system_id_values": ids, "proof_system_values": ["longfellow-libzk-v1"] } } },
  })
}

fn request(host: &str, nonce: &str, range: Option<&str>) -> Value {
  request_for(host, nonce, range, &[DECOY_ID])
}

fn handover(req: &Value) -> Value {
  json!({ "client_id": req["client_id"], "nonce": req["nonce"], "response_uri": req["response_uri"], "jwk_thumbprint": b64url(&THUMBPRINT) })
}

/// A holder as the phone sends it: a credential (the v0.6 one, unless said otherwise), the device
/// key, the seed and the birth date.
#[derive(Clone)]
struct Holder {
  credential: Value,
  device_key: Value,
  secret_seed: String,
  birth_date: String,
}

fn holders(file: std::path::PathBuf, version: &str) -> Vec<Holder> {
  json_file(file)["holders"]
    .as_array()
    .unwrap()
    .iter()
    .map(|h| Holder {
      credential: h[version]["credential"].clone(),
      device_key: h["device_key"].clone(),
      secret_seed: h["secret_seed"].as_str().unwrap().into(),
      birth_date: h[version]["birth_date"].as_str().unwrap().into(),
    })
    .collect()
}

/// A holder of the circuit package's synthetic set (TEST ONLY: signed with the rulebook vectors'
/// TEST Document Signer, over the vectors' device key).
fn synthetic(name: &str) -> Holder {
  let data = here("nym-auth-zk-decoy/tests/data");
  let h = &json_file(data.join("decoy_synthetic_holders.json"))["holders"][name];
  let d = &json_file(data.join("decoy_test_vectors.json"))["keys"]["device"];
  let k = |n: &str| b64url(&hex::decode(d[n].as_str().unwrap()).unwrap());
  Holder {
    credential: json!({ "format": "mso_mdoc", "doctype": DOC_TYPE, "rulebook": "0.6", "issuer_signed": b64url(&hex::decode(h["issuer_signed"].as_str().unwrap()).unwrap()) }),
    device_key: json!({ "kty": "EC", "crv": "P-256", "x": k("x"), "y": k("y"), "d": k("d") }),
    secret_seed: h["secret_seed"].as_str().unwrap().into(),
    birth_date: h["birth_date"].as_str().unwrap().into(),
  }
}

fn issuer_signed(h: &Holder) -> Vec<u8> {
  unb64url("issuer_signed", h.credential["issuer_signed"].as_str().unwrap()).unwrap()
}

fn present_as(p: &Prover, h: &Holder, req: &Value, system_id: &str, rulebook: &str, parallel: bool) -> Result<Value, nym_longfellow::error::Refusal> {
  let sign: SignInput = serde_json::from_value(json!({ "device_key": h.device_key, "doc_type": DOC_TYPE, "handover": handover(req) })).unwrap();
  let signed = p.sign(&sign)?;
  let input: WitnessInput = serde_json::from_value(json!({
    "system_id": system_id, "credential_query_id": "nym_attestation",
    "request": req, "handover": handover(req), "credential": h.credential,
    "secret_seed": h.secret_seed, "birth_date": h.birth_date, "device_signature": signed.device_signature,
    "rulebook": rulebook, "parallel": parallel,
  }))
  .unwrap();
  let w = p.witness(&input)?;
  Ok(p.prove(w).unwrap())
}

fn present(p: &Prover, h: &Holder, req: &Value) -> Result<Value, nym_longfellow::error::Refusal> {
  present_as(p, h, req, DECOY_ID, "0.6", false)
}

fn verify_as(v: &Verifier, req: &Value, presentation: &str, now: &str, learned: &[String], rulebook: &str, parallel: bool) -> Value {
  let input: VerifyInput = serde_json::from_value(json!({
    "request": req, "credential_query_id": "nym_attestation", "presentation": presentation, "handover": handover(req),
    "now": now, "learned_issuers": learned, "rulebook": rulebook, "parallel": parallel,
  }))
  .unwrap();
  v.verify(&input)
}

fn verify(v: &Verifier, req: &Value, presentation: &str, now: &str) -> Value {
  verify_as(v, req, presentation, now, &[], "0.6", false)
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

fn base64(der: &[u8]) -> String {
  use base64::Engine;
  base64::engine::general_purpose::STANDARD.encode(der)
}

/// Every demo holder's v0.6 credential is the decoy layout (the crate's strict parse) and opens
/// with its seed and birth date; nym-issuer checks its credentials against a copy of the layout's
/// template, which must be the crate's.
#[test]
fn demo_v06_credentials_are_the_decoy_layout() {
  let file = json_file(root("app/wallet/demo-wallet.json"));
  for (k, h) in holders(root("app/wallet/demo-wallet.json"), "v06").iter().enumerate() {
    assert_eq!(h.credential["rulebook"], "0.6");
    let c = decoy::credential(&issuer_signed(h)).unwrap_or_else(|e| panic!("holder {k}: {e}"));
    let seed = hex::decode(&h.secret_seed).unwrap();
    assert_eq!(c.parsed.bsc, sha256(&[&seed[..], h.birth_date.as_bytes()].concat()), "holder {k}: bsc");
    let private_seed = hex::decode(file["holders"][k]["v06"]["private_seed"].as_str().unwrap()).unwrap();
    assert_eq!(c.parsed.psc, sha256(&private_seed), "holder {k}: psc");
    // The same seed, birth date, private_seed and Document Signer as the holder's v0.5 credential.
    assert_eq!(file["holders"][k]["v06"]["birth_date"], file["holders"][k]["v05"]["birth_date"]);
    assert_eq!(file["holders"][k]["v06"]["private_seed"], file["holders"][k]["v05"]["private_seed"]);
    assert_eq!(c.valid_until.text(), "9999-12-31T23:59:59Z");
  }
  let copy: String = std::fs::read_to_string(root("native/vega/issuer/src/v06_template.hex")).unwrap().split_whitespace().collect();
  assert_eq!(hex::decode(copy).unwrap(), v6::mdoc::TEMPLATE.to_vec(), "nym-issuer's v06_template.hex is not the crate's TEMPLATE");
}

/// shared/registry/circuits.ts lists the decoy circuits' public inputs in the adapter's order, with
/// values = hash + signature elements.
#[test]
fn registry_entry_matches_the_adapter() {
  let ts = std::fs::read_to_string(root("shared/registry/circuits.ts")).unwrap();
  let start = ts.find("const LONGFELLOW_DECOY_PUBLIC_INPUTS").expect("the registry's decoy inputs");
  let block = &ts[start..start + ts[start..].find("\n]").unwrap()];
  let listed: Vec<(String, usize)> = block
    .lines()
    .filter_map(|l| {
      let name = l.split("name: '").nth(1)?.split('\'').next()?;
      let values = l.split("values: ").nth(1)?.split(',').next()?.trim().parse().ok()?;
      Some((name.to_string(), values))
    })
    .collect();
  let adapter: Vec<(String, usize)> = decoy::PUBLIC_INPUTS.iter().map(|(n, h, s)| (n.to_string(), h + s)).collect();
  assert_eq!(listed, adapter);
  assert!(ts.contains(&format!("sha256: '{}'", DECOY_ID.trim_start_matches("urn:circuits:sha256:"))));
}

#[test]
fn v06_holders_prove_and_the_verifier_refuses() {
  let dir = here("circuits/mdoc");
  let prover = Prover::load(&dir).unwrap();
  let pem = std::fs::read_to_string(root("native/vega/demo/document-signer.pem")).unwrap();
  let verifier = Verifier::load(&dir, &pem, 300).unwrap();
  assert_eq!(decoy::system_id(), DECOY_ID);
  let all = holders(root("app/wallet/demo-wallet.json"), "v06");
  let today = dates::now().unwrap().date;
  let teen = all.iter().find(|h| (13..=17).contains(&age_on(&h.birth_date, &today))).expect("a teen").clone();
  let adult = all.iter().find(|h| age_on(&h.birth_date, &today) >= 18).expect("an adult").clone();
  let cores = nym_longfellow::threads::cores();

  // Accepted: every holder without an age check and in the range it fits, on one thread and on
  // every core; the pseudonym is the bsc circuits' for the same seed.
  for h in &all {
    let fits = if age_on(&h.birth_date, &today) >= 18 { "18+" } else { "13-17" };
    for (range, parallel) in [(None, false), (Some(fits), false), (Some(fits), true)] {
      let req = request("community.example", "v06-accept-0123456789abcdef012345", range);
      let out = present_as(&prover, h, &req, DECOY_ID, "0.6", parallel).unwrap_or_else(|e| panic!("{} {range:?}: {e:?}", h.birth_date));
      assert_eq!(out["system_id"], DECOY_ID);
      assert_eq!(out["metrics"]["threads"], if parallel { cores } else { 1 });
      let pres = out["presentation"].as_str().unwrap();
      let v = verify_as(&verifier, &req, pres, &dates::now().unwrap().text(), &[], "0.6", parallel);
      assert_eq!(v["ok"], true, "{} {range:?}: {v}", h.birth_date);
      assert_eq!(v["metrics"]["threads"], if parallel { cores } else { 1 });
      let seed: [u8; 16] = nym_longfellow::unhex("seed", &h.secret_seed).unwrap();
      let nym = nym_longfellow::hex(&v6::witness::pseudonym(&seed, &sha256(b"x509_san_dns:community.example")));
      assert_eq!(v["results"]["nym"].as_str().unwrap(), nym);
      assert_eq!(nym, nym_longfellow::hex(&nym_auth_zk::witness::pseudonym(&seed, &sha256(b"x509_san_dns:community.example"))), "the same pseudonym as under v0.5");
      assert_eq!(v["results"].as_object().unwrap().len(), 1, "an assertion has no output");
      assert_eq!(v["bounds"].is_null(), range.is_none(), "{v}");
      println!(
        "{} {range:?} on {} thread(s): proof {} B, prebuild {} ms, prove {} ms, verify {} ms",
        h.birth_date, out["metrics"]["threads"], out["metrics"]["proof_bytes"], out["metrics"]["prebuild_ms"], out["metrics"]["prove_ms"], v["metrics"]["verify_ms"]
      );
    }
  }

  let req = request("community.example", "v06-refuse-0123456789abcdef012345", Some("13-17"));
  let out = present(&prover, &teen, &req).unwrap();
  let pres = out["presentation"].as_str().unwrap().to_string();
  let now = dates::now().unwrap().text();
  // proof_time within the tolerance.
  assert_eq!(verify(&verifier, &req, &pres, &now_plus(120))["ok"], true);

  // Refused by the verifier.
  let other_nonce = request("community.example", "v06-another-nonce-0123456789abcd", Some("13-17"));
  assert_eq!(code(&verify(&verifier, &other_nonce, &pres, &now)), "proof_invalid");
  let other_client = request("other.example", "v06-refuse-0123456789abcdef012345", Some("13-17"));
  assert_eq!(code(&verify(&verifier, &other_client, &pres, &now)), "proof_invalid");
  let other_range = request("community.example", "v06-refuse-0123456789abcdef012345", Some("14-17"));
  let r = verify(&verifier, &other_range, &pres, &now);
  assert_eq!((code(&r), r["input"].as_str()), ("proof_invalid", Some("hash")), "{r}");
  let tampered = edit(&pres, |p| p.proof[1000] ^= 1);
  assert!(matches!(code(&verify(&verifier, &req, &tampered, &now)), "proof_invalid" | "proof_encoding"));
  let truncated = edit(&pres, |p| p.proof.truncate(p.proof.len() / 2));
  assert_eq!(code(&verify(&verifier, &req, &truncated, &now)), "proof_encoding");
  assert_eq!(code(&verify(&verifier, &req, &pres, &now_plus(3600))), "proof_time");
  let empty = edit(&pres, |p| p.results.clear());
  assert_eq!(code(&verify(&verifier, &req, &empty, &now)), "results");
  let missing = edit(&pres, |p| p.results[0].0 = "pseudonym".into());
  assert_eq!(code(&verify(&verifier, &req, &missing, &now)), "results");
  let extra = edit(&pres, |p| p.results.push(("age".into(), ResultValue::True)));
  assert_eq!(code(&verify(&verifier, &req, &extra, &now)), "results");
  let other_nym = edit(&pres, |p| p.results[0].1 = ResultValue::Pseudonym([7; 32]));
  assert_eq!(code(&verify(&verifier, &req, &other_nym, &now)), "proof_invalid");
  // One set per version: a v0.6 presentation read under 0.5, and a v0.5 one under 0.6.
  assert_eq!(code(&verify_as(&verifier, &req, &pres, &now, &[], "0.5", false)), "circuit");
  let teen05 = holders(root("app/wallet/demo-wallet.json"), "v05").into_iter().find(|h| h.birth_date == teen.birth_date).unwrap();
  let req05 = request_for("community.example", "v06-v05-0123456789abcdef01234567", Some("13-17"), &[BSC_ID]);
  let out05 = present_as(&prover, &teen05, &req05, BSC_ID, "0.5", false).unwrap();
  let pres05 = out05["presentation"].as_str().unwrap();
  assert_eq!(verify_as(&verifier, &req05, pres05, &now, &[], "0.5", false)["ok"], true);
  assert_eq!(code(&verify_as(&verifier, &req05, pres05, &now, &[], "0.6", false)), "circuit");

  // An unknown certificate (the package's TEST Document Signer, holder C): refused with it,
  // accepted once learned.
  let c = synthetic("C");
  let req2 = request("community.example", "v06-issuer-0123456789abcdef012345", None);
  let out2 = present(&prover, &c, &req2).unwrap();
  let pres2 = out2["presentation"].as_str().unwrap();
  let r = verify(&verifier, &req2, pres2, &now);
  assert_eq!(code(&r), "issuer_key_set", "{r}");
  let cert = r["certificate"].as_str().expect("the untrusted certificate").to_string();
  assert_eq!(verify_as(&verifier, &req2, pres2, &now, &[cert], "0.6", false)["ok"], true);

  // Refused by the prover.
  let r18 = request("community.example", "v06-prover-0123456789abcdef0123456", Some("18+"));
  assert_eq!(present(&prover, &teen, &r18).unwrap_err().error, "unsatisfiable");
  assert_eq!(present(&prover, &adult, &req).unwrap_err().error, "unsatisfiable");
  // Holder D's credential ended at 2026-10-27T12:00:00Z.
  let e = present(&prover, &synthetic("D"), &request("community.example", "v06-expired-0123456789abcdef0123", None)).unwrap_err();
  assert_eq!(e.error, "unsatisfiable", "{e:?}");
  let wrong_seed = Holder { secret_seed: "00".repeat(16), ..teen.clone() };
  assert_eq!(present(&prover, &wrong_seed, &req).unwrap_err().error, "bad_credential");
  let wrong_birth = Holder { birth_date: "2011-03-15".into(), ..teen.clone() };
  assert_eq!(present(&prover, &wrong_birth, &req).unwrap_err().error, "bad_credential");
  let compact = Holder { credential: teen05.credential.clone(), ..teen.clone() };
  let e = present(&prover, &compact, &req).unwrap_err();
  assert_eq!(e.error, "bad_credential", "{e:?}");
  let both = request_for("community.example", "v06-binding-0123456789abcdef01234", None, &[DECOY_ID, BSC_ID]);
  assert_eq!(present_as(&prover, &teen, &both, DECOY_ID, "0.5", false).unwrap_err().error, "unsupported_circuit");
  assert_eq!(present_as(&prover, &teen05, &both, BSC_ID, "0.6", false).unwrap_err().error, "unsupported_circuit");
}

/// validUntil is inclusive: the package's holder D (valid until 2026-10-27T12:00:00Z, born on C of
/// 13-17 that day) proves at proof_time = validUntil and the verifier accepts it at that time; one
/// second later the crate refuses to prove. Fixed times, through the crate's prover (the addon's
/// takes the clock).
#[test]
fn valid_until_is_inclusive() {
  let dir = here("circuits/mdoc");
  let d = synthetic("D");
  let raw = issuer_signed(&d);
  let cred = decoy::credential(&raw).unwrap();
  let until = cred.valid_until.text();
  assert_eq!(until, "2026-10-27T12:00:00Z");
  let pem = std::fs::read_to_string(root("native/vega/demo/document-signer.pem")).unwrap();
  let verifier = Verifier::load(&dir, &pem, 300).unwrap();
  let signer = x509::parse(&cred.document_signer).unwrap();
  let req = request("community.example", "v06-until-0123456789abcdef0123456", Some("13-17"));
  let ro: nym_longfellow::request::RequestObject = serde_json::from_value(req.clone()).unwrap();
  let h: nym_longfellow::handover::Handover = serde_json::from_value(handover(&req)).unwrap();
  let key = unb64url("d", d.device_key["d"].as_str().unwrap()).unwrap();
  let device = SigningKey::from_bytes(&<[u8; 32]>::try_from(key).unwrap().into()).unwrap();
  let holder = v6::Holder {
    credential: &raw,
    secret_seed: hex::decode(&d.secret_seed).unwrap().try_into().unwrap(),
    birth_date: d.birth_date.as_bytes().try_into().unwrap(),
  };
  let prover = v6::Prover::load().unwrap();
  let prove_at = |t: &str| {
    let r = decoy::request(&signer.key, t, &ro, "nym_attestation", &h).unwrap();
    let sig: Signature = device.sign(&v6::Prover::device_signed_bytes(&r));
    prover.prove(&r, &holder, &sig.to_bytes().into(), &mut SecureRandomEngine::new())
  };
  let p = prove_at(&until).expect("proves at validUntil");
  let wire = Presentation {
    system_id: DECOY_ID.into(),
    proof: p.proof,
    issuer_key_set: vec![cred.document_signer.clone()],
    proof_time: until.clone(),
    results: vec![("nym".into(), ResultValue::Pseudonym(p.pseudonym))],
  };
  let v = verify_as(&verifier, &req, &b64url(&wire.encode().unwrap()), &until, &[base64(&cred.document_signer)], "0.6", false);
  assert_eq!(v["ok"], true, "{v}");
  let after = dates::from_unix(dates::unix(&dates::date_time(&until).unwrap()) + 1).unwrap().text();
  assert_eq!(prove_at(&after).unwrap_err(), v6::Error::Holder("the credential is not valid at proof_time"));
}
