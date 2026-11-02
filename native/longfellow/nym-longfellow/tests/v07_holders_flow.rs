//! Rulebook v0.7 end to end on the `nym-auth-zk-v07` circuits (the v0.7 layout: AES-128
//! commitments, the device key compressed, the pseudonym with `prf` `aes-128`), through the
//! holder's three steps (`Prover::sign`, `witness`, `prove`) and `Verifier::verify` with
//! `rulebook: "0.7"`, on the demo holders' v0.7 credentials (`app/wallet/demo-wallet.json`, each
//! holder's `v07`, issued by nym-issuer --v07). The circuit package's VERIFIER-AGENT.md §4 lists the
//! cases. Also: every demo v0.7 credential passes the crate's strict layout parse and opens with its
//! seeds, nym-issuer's copy of the layout template is the crate's, and the site's registry entry
//! (shared/registry/circuits.ts) lists the adapter's public inputs with the same element counts.

use nym_auth_zk_v07 as v7;
use nym_longfellow::circuit::DOC_TYPE;
use nym_longfellow::presentation::{Presentation, ResultValue};
use nym_longfellow::prover::{Prover, SignInput, WitnessInput};
use nym_longfellow::verifier::{Verifier, VerifyInput};
use nym_longfellow::{b64url, dates, sha256, unb64url, v07, x509};
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
const DECOY_ID: &str = "urn:circuits:sha256:5d7d2b5d094032df5b02f576d2ae7b99d3f0932d47516336693f8d670cfd63ac";
const V07_ID: &str = "urn:circuits:sha256:218a72dea317cfcde2e715860e6b3a5dda2c67260f4cf9e8311c62ef900c34bd";

fn request_for(host: &str, nonce: &str, range: Option<&str>, ids: &[&str], prf: &str) -> Value {
  let mut req = vec![json!({ "fn_id": "pseudonym", "return": "nym", "params": { "config": "known-offender-matching-ssc", "ver": 1, "prf": prf } })];
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
  request_for(host, nonce, range, &[V07_ID], "aes-128")
}

fn handover(req: &Value) -> Value {
  json!({ "client_id": req["client_id"], "nonce": req["nonce"], "response_uri": req["response_uri"], "jwk_thumbprint": b64url(&THUMBPRINT) })
}

/// A holder as the phone sends it: a credential (the v0.7 one, unless said otherwise), the device
/// key, the seed and the birth date.
#[derive(Clone)]
struct Holder {
  credential: Value,
  device_key: Value,
  secret_seed: String,
  birth_date: String,
}

fn holders(version: &str) -> Vec<Holder> {
  json_file(root("app/wallet/demo-wallet.json"))["holders"]
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
/// TEST Document Signer; over the vectors' device key, or holder E's own, whose y is odd).
fn synthetic(name: &str) -> Holder {
  use p256::elliptic_curve::sec1::ToEncodedPoint;
  let data = here("nym-auth-zk-v07/tests/data");
  let h = &json_file(data.join("v07_synthetic_holders.json"))["holders"][name];
  let d: [u8; 32] = match h["device_d"].as_str() {
    Some(dh) => nym_longfellow::unhex("device_d", dh).unwrap(),
    None => nym_longfellow::unhex("d", json_file(data.join("v07_test_vectors.json"))["keys"]["device"]["d"].as_str().unwrap()).unwrap(),
  };
  let pt = p256::SecretKey::from_slice(&d).unwrap().public_key().to_encoded_point(false);
  Holder {
    credential: json!({ "format": "mso_mdoc", "doctype": DOC_TYPE, "rulebook": "0.7", "issuer_signed": b64url(&hex::decode(h["issuer_signed"].as_str().unwrap()).unwrap()) }),
    device_key: json!({ "kty": "EC", "crv": "P-256", "x": b64url(pt.x().unwrap()), "y": b64url(pt.y().unwrap()), "d": b64url(&d) }),
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
  present_as(p, h, req, V07_ID, "0.7", false)
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
  verify_as(v, req, presentation, now, &[], "0.7", false)
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

/// The aes-128 pseudonym of a seed for a host: AES-128(seed, H[0..16]) ‖ AES-128(seed, H[16..32]).
fn aes_nym(seed_hex: &str, host: &str) -> String {
  let seed: [u8; 16] = nym_longfellow::unhex("seed", seed_hex).unwrap();
  let h = v7::witness::nym_block(&sha256(format!("x509_san_dns:{host}").as_bytes()));
  nym_longfellow::hex(&v7::witness::pseudonym(&seed, &h))
}

/// Every demo holder's v0.7 credential is the v0.7 layout (the crate's strict parse, y recovered
/// from x and the sign) and opens with its seeds; the same seeds, birth date, device key and
/// Document Signer as its v0.6 credential; nym-issuer's copy of the layout template is the crate's.
#[test]
fn demo_v07_credentials_are_the_v07_layout() {
  use p256::elliptic_curve::sec1::ToEncodedPoint;
  let file = json_file(root("app/wallet/demo-wallet.json"));
  for (k, h) in holders("v07").iter().enumerate() {
    assert_eq!(h.credential["rulebook"], "0.7");
    let c = v07::credential(&issuer_signed(h)).unwrap_or_else(|e| panic!("holder {k}: {e}"));
    let seed: [u8; 16] = nym_longfellow::unhex("seed", &h.secret_seed).unwrap();
    assert_eq!(c.parsed.bsc, v7::aes::bsc(&seed, h.birth_date.as_bytes().try_into().unwrap()), "holder {k}: bsc");
    let private_seed: [u8; 16] = nym_longfellow::unhex("private_seed", file["holders"][k]["v07"]["private_seed"].as_str().unwrap()).unwrap();
    assert_eq!(c.parsed.psc, v7::aes::psc(&private_seed), "holder {k}: psc");
    // The device key: the holder's, y recovered from x and the sign.
    let d = unb64url("d", h.device_key["d"].as_str().unwrap()).unwrap();
    let pt = p256::SecretKey::from_slice(&d).unwrap().public_key().to_encoded_point(false);
    assert_eq!((&c.parsed.device_x[..], &c.parsed.device_y[..]), (pt.x().unwrap().as_slice(), pt.y().unwrap().as_slice()), "holder {k}: device key");
    // The same values as the holder's v0.6 credential, and the same Document Signer.
    for f in ["birth_date", "private_seed"] {
      assert_eq!(file["holders"][k]["v07"][f], file["holders"][k]["v06"][f], "holder {k}: {f}");
    }
    let c6 = nym_longfellow::decoy::credential(&unb64url("v06", file["holders"][k]["v06"]["credential"]["issuer_signed"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(c.document_signer, c6.document_signer, "holder {k}: one Document Signer");
    assert_eq!(c.valid_until.text(), "9999-12-31T23:59:59Z");
  }
  let copy: String = std::fs::read_to_string(root("native/vega/issuer/src/v07_template.hex")).unwrap().split_whitespace().collect();
  assert_eq!(hex::decode(copy).unwrap(), v7::mdoc::TEMPLATE.to_vec(), "nym-issuer's v07_template.hex is not the crate's TEMPLATE");
}

/// shared/registry/circuits.ts lists the v0.7 circuits' public inputs in the adapter's order, with
/// values = hash + signature elements, and the archive's hash.
#[test]
fn registry_entry_matches_the_adapter() {
  let ts = std::fs::read_to_string(root("shared/registry/circuits.ts")).unwrap();
  let start = ts.find("const LONGFELLOW_V07_PUBLIC_INPUTS").expect("the registry's v0.7 inputs");
  let block = &ts[start..start + ts[start..].find("\n]").unwrap()];
  let listed: Vec<(String, usize)> = block
    .lines()
    .filter_map(|l| {
      let name = l.split("name: '").nth(1)?.split('\'').next()?;
      let values = l.split("values: ").nth(1)?.split(',').next()?.trim().parse().ok()?;
      Some((name.to_string(), values))
    })
    .collect();
  let adapter: Vec<(String, usize)> = v07::PUBLIC_INPUTS.iter().map(|(n, h, s)| (n.to_string(), h + s)).collect();
  assert_eq!(listed, adapter);
  assert_eq!(v07::PUBLIC_INPUTS.iter().map(|p| p.1).sum::<usize>() + 1, 267);
  assert_eq!(v07::PUBLIC_INPUTS.iter().map(|p| p.2).sum::<usize>() + 1, 899);
  assert!(ts.contains(&format!("sha256: '{}'", V07_ID.trim_start_matches("urn:circuits:sha256:"))));
  assert!(ts.contains(&format!("name: '{}'", v07::ARTIFACT)));
}

#[test]
fn v07_holders_prove_and_the_verifier_refuses() {
  let dir = here("circuits/mdoc");
  let prover = Prover::load(&dir).unwrap();
  let pem = std::fs::read_to_string(root("native/vega/demo/document-signer.pem")).unwrap();
  let verifier = Verifier::load(&dir, &pem, 300).unwrap();
  assert_eq!(v07::system_id(), V07_ID);
  let all = holders("v07");
  let today = dates::now().unwrap().date;
  let teen = all.iter().find(|h| (13..=17).contains(&age_on(&h.birth_date, &today))).expect("a teen").clone();
  let adult = all.iter().find(|h| age_on(&h.birth_date, &today) >= 18).expect("an adult").clone();
  let cores = nym_longfellow::threads::cores();

  // Accepted: every holder without an age check and in the range it fits, on one thread and on
  // every core; the pseudonym is aes-128's, not the v0.6 one.
  for h in &all {
    let fits = if age_on(&h.birth_date, &today) >= 18 { "18+" } else { "13-17" };
    for (range, parallel) in [(None, false), (Some(fits), false), (Some(fits), true)] {
      let req = request("community.example", "v07-accept-0123456789abcdef012345", range);
      let out = present_as(&prover, h, &req, V07_ID, "0.7", parallel).unwrap_or_else(|e| panic!("{} {range:?}: {e:?}", h.birth_date));
      assert_eq!(out["system_id"], V07_ID);
      assert_eq!(out["metrics"]["threads"], if parallel { cores } else { 1 });
      let pres = out["presentation"].as_str().unwrap();
      let v = verify_as(&verifier, &req, pres, &dates::now().unwrap().text(), &[], "0.7", parallel);
      assert_eq!(v["ok"], true, "{} {range:?}: {v}", h.birth_date);
      assert_eq!(v["metrics"]["threads"], if parallel { cores } else { 1 });
      let nym = aes_nym(&h.secret_seed, "community.example");
      assert_eq!(v["results"]["nym"].as_str().unwrap(), nym);
      let seed: [u8; 16] = nym_longfellow::unhex("seed", &h.secret_seed).unwrap();
      assert_ne!(nym, nym_longfellow::hex(&nym_auth_zk_decoy::witness::pseudonym(&seed, &sha256(b"x509_san_dns:community.example"))), "not the v0.6 pseudonym");
      assert_eq!(v["results"].as_object().unwrap().len(), 1, "an assertion has no output");
      assert_eq!(v["bounds"].is_null(), range.is_none(), "{v}");
      println!(
        "{} {range:?} on {} thread(s): proof {} B, prebuild {} ms, prove {} ms, verify {} ms",
        h.birth_date, out["metrics"]["threads"], out["metrics"]["proof_bytes"], out["metrics"]["prebuild_ms"], out["metrics"]["prove_ms"], v["metrics"]["verify_ms"]
      );
    }
  }

  let req = request("community.example", "v07-refuse-0123456789abcdef012345", Some("13-17"));
  let out = present(&prover, &teen, &req).unwrap();
  let pres = out["presentation"].as_str().unwrap().to_string();
  let now = dates::now().unwrap().text();
  // proof_time within the tolerance.
  assert_eq!(verify(&verifier, &req, &pres, &now_plus(120))["ok"], true);

  // Refused by the verifier.
  let other_nonce = request("community.example", "v07-another-nonce-0123456789abcd", Some("13-17"));
  assert_eq!(code(&verify(&verifier, &other_nonce, &pres, &now)), "proof_invalid");
  let other_client = request("other.example", "v07-refuse-0123456789abcdef012345", Some("13-17"));
  assert_eq!(code(&verify(&verifier, &other_client, &pres, &now)), "proof_invalid");
  let other_range = request("community.example", "v07-refuse-0123456789abcdef012345", Some("14-17"));
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
  // One set per version: a v0.7 presentation read under 0.6, and a v0.6 one under 0.7.
  assert_eq!(code(&verify_as(&verifier, &req, &pres, &now, &[], "0.6", false)), "circuit");
  let teen06 = holders("v06").into_iter().find(|h| h.birth_date == teen.birth_date).unwrap();
  let req06 = request_for("community.example", "v07-v06-0123456789abcdef01234567", Some("13-17"), &[DECOY_ID], "sha-256");
  let out06 = present_as(&prover, &teen06, &req06, DECOY_ID, "0.6", false).unwrap();
  let pres06 = out06["presentation"].as_str().unwrap();
  assert_eq!(verify_as(&verifier, &req06, pres06, &now, &[], "0.6", false)["ok"], true);
  assert_eq!(code(&verify_as(&verifier, &req06, pres06, &now, &[], "0.7", false)), "circuit");

  // An unknown certificate (the package's TEST Document Signer): refused with it, accepted once
  // learned. Holder C (y even) and holder E (its own device key, y odd: -3 true).
  for name in ["C", "E"] {
    let h = synthetic(name);
    let c = v07::credential(&issuer_signed(&h)).unwrap();
    assert_eq!(c.parsed.sig_structure[v7::mdoc::DEVICE_SIGN_AT] == 0xf5, name == "E", "{name}: the sign byte");
    let req2 = request("community.example", "v07-issuer-0123456789abcdef012345", None);
    let out2 = present(&prover, &h, &req2).unwrap();
    let pres2 = out2["presentation"].as_str().unwrap();
    let r = verify(&verifier, &req2, pres2, &now);
    assert_eq!(code(&r), "issuer_key_set", "{name}: {r}");
    let cert = r["certificate"].as_str().expect("the untrusted certificate").to_string();
    let ok = verify_as(&verifier, &req2, pres2, &now, &[cert], "0.7", true);
    assert_eq!(ok["ok"], true, "{name}: {ok}");
    assert_eq!(ok["results"]["nym"].as_str().unwrap(), aes_nym(&h.secret_seed, "community.example"), "{name}: the pseudonym");
  }

  // Refused by the prover.
  let r18 = request("community.example", "v07-prover-0123456789abcdef0123456", Some("18+"));
  assert_eq!(present(&prover, &teen, &r18).unwrap_err().error, "unsatisfiable");
  assert_eq!(present(&prover, &adult, &req).unwrap_err().error, "unsatisfiable");
  // Holder D's credential ended at 2026-10-27T12:00:00Z.
  let e = present(&prover, &synthetic("D"), &request("community.example", "v07-expired-0123456789abcdef0123", None)).unwrap_err();
  assert_eq!(e.error, "unsatisfiable", "{e:?}");
  let wrong_seed = Holder { secret_seed: "00".repeat(16), ..teen.clone() };
  assert_eq!(present(&prover, &wrong_seed, &req).unwrap_err().error, "bad_credential");
  let wrong_birth = Holder { birth_date: "2011-03-15".into(), ..teen.clone() };
  assert_eq!(present(&prover, &wrong_birth, &req).unwrap_err().error, "bad_credential");
  // The holder's v0.6 (decoy) credential with the v0.7 circuits.
  let decoy = Holder { credential: teen06.credential.clone(), ..teen.clone() };
  let e = present(&prover, &decoy, &req).unwrap_err();
  assert_eq!(e.error, "bad_credential", "{e:?}");
  let both = request_for("community.example", "v07-binding-0123456789abcdef01234", None, &[V07_ID, DECOY_ID], "aes-128");
  assert_eq!(present_as(&prover, &teen, &both, V07_ID, "0.6", false).unwrap_err().error, "unsupported_circuit");
  assert_eq!(present_as(&prover, &teen06, &both, DECOY_ID, "0.7", false).unwrap_err().error, "unsupported_circuit");
  let sha = request_for("community.example", "v07-prf-0123456789abcdef0123456789", None, &[V07_ID], "sha-256");
  assert_eq!(present(&prover, &teen, &sha).unwrap_err().error, "unsupported_config");
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
  let cred = v07::credential(&raw).unwrap();
  let until = cred.valid_until.text();
  assert_eq!(until, "2026-10-27T12:00:00Z");
  let pem = std::fs::read_to_string(root("native/vega/demo/document-signer.pem")).unwrap();
  let verifier = Verifier::load(&dir, &pem, 300).unwrap();
  let signer = x509::parse(&cred.document_signer).unwrap();
  let req = request("community.example", "v07-until-0123456789abcdef0123456", Some("13-17"));
  let ro: nym_longfellow::request::RequestObject = serde_json::from_value(req.clone()).unwrap();
  let h: nym_longfellow::handover::Handover = serde_json::from_value(handover(&req)).unwrap();
  let key = unb64url("d", d.device_key["d"].as_str().unwrap()).unwrap();
  let device = SigningKey::from_bytes(&<[u8; 32]>::try_from(key).unwrap().into()).unwrap();
  let holder = v7::Holder {
    credential: &raw,
    secret_seed: hex::decode(&d.secret_seed).unwrap().try_into().unwrap(),
    birth_date: d.birth_date.as_bytes().try_into().unwrap(),
  };
  let prover = v7::Prover::load().unwrap();
  let prove_at = |t: &str| {
    let r = v07::request(&signer.key, t, &ro, "nym_attestation", &h).unwrap();
    let sig: Signature = device.sign(&v7::Prover::device_signed_bytes(&r));
    prover.prove(&r, &holder, &sig.to_bytes().into(), &mut SecureRandomEngine::new())
  };
  let p = prove_at(&until).expect("proves at validUntil");
  let wire = Presentation {
    system_id: V07_ID.into(),
    proof: p.proof,
    issuer_key_set: vec![cred.document_signer.clone()],
    proof_time: until.clone(),
    results: vec![("nym".into(), ResultValue::Pseudonym(p.pseudonym))],
  };
  let v = verify_as(&verifier, &req, &b64url(&wire.encode().unwrap()), &until, &[base64(&cred.document_signer)], "0.7", false);
  assert_eq!(v["ok"], true, "{v}");
  let after = dates::from_unix(dates::unix(&dates::date_time(&until).unwrap()) + 1).unwrap().text();
  assert_eq!(prove_at(&after).unwrap_err(), v7::Error::Holder("the credential is not valid at proof_time"));
}
