//! Cross-checks of Community's own protocol code against `nym-auth-zk-decoy` (the rulebook v0.6
//! circuits, decoy-digest layout), on the package's decoy test vectors
//! (`nym-auth-zk-decoy/tests/data/decoy_test_vectors.json`: the rulebook v0.5 vectors' keys, openings
//! and sessions, the credential re-issued in the decoy layout with the vectors' TEST Document Signer
//! key). Requests are read under `Rulebook::V06`, which keeps v0.5's request rules.
//! SHIPPED WITH THE CIRCUIT PACKAGE nym-auth-longfellow-decoy-v1: drop into
//! `native/longfellow/nym-longfellow/tests/`.
//!
//! 1. The SessionTranscript and the device message (B.2.6.1) are byte-identical on both sides.
//! 2. The v0.5/v0.6 range bounds agree (`dates::range_bounds` and `nym_auth_zk::AgeRange::bounds`).
//! 3. The system_id is the archive's SHA-256.
//! 4. End to end through `bsc.rs`: a Request Object and handover as the site holds them, the
//!    issuer key from the Document Signer certificate, the device signature as `Prover::sign`
//!    makes it, prove, encode as ZkpPresentation, decode, verify; and refusals for another nonce,
//!    another client_id, another range and a tampered proof.

use nym_auth_zk_decoy as v5;
use nym_longfellow::handover::{self, Handover};
use nym_longfellow::presentation::{Presentation, ResultValue};
use nym_longfellow::request::{RequestObject, Rulebook, statement_for};
use nym_longfellow::{dates, decoy as bsc, x509};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use runtime_random::SecureRandomEngine;
use serde_json::{Value, json};

fn vectors(name: &str) -> Value {
  let p = format!("{}/../nym-auth-zk-decoy/tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
  serde_json::from_str(&std::fs::read_to_string(p).expect("vectors")).expect("json")
}

fn s(v: &Value, path: &[&str]) -> String {
  path.iter().fold(v, |x, k| &x[*k]).as_str().unwrap_or_else(|| panic!("{}", path.join("."))).to_string()
}

fn bytes(h: &str) -> Vec<u8> {
  hex::decode(h).expect("hex")
}

fn arr<const N: usize>(h: &str) -> [u8; N] {
  bytes(h).try_into().expect("length")
}

fn handover_of(v: &Value) -> Handover {
  let i = &v["sessions"]["redirect"]["inputs"];
  Handover {
    client_id: i["client_id"].as_str().unwrap().into(),
    nonce: i["nonce"].as_str().unwrap().into(),
    response_uri: i["response_uri"].as_str().unwrap().into(),
    jwk_thumbprint: i["jwk_thumbprint"].as_str().map(|t| nym_longfellow::b64url(&bytes(t))),
  }
}

fn request_object(h: &Handover, range: Option<&str>) -> RequestObject {
  let mut req = vec![json!({ "fn_id": "pseudonym", "return": "nym",
    "params": { "config": "known-offender-matching-ssc", "ver": 1, "prf": "sha-256" } })];
  if let Some(r) = range {
    req.push(json!({ "fn_id": "age_check", "params": { "range": r } }));
  }
  serde_json::from_value(json!({
    "client_id": h.client_id, "nonce": h.nonce, "response_uri": h.response_uri,
    "dcql_query": { "credentials": [{ "id": "q", "format": "zkp_req",
      "meta": { "source_format": "mso_mdoc", "doctype_value": "eu.europa.ec.eudi.nym_auth.1" },
      "_req": req }] },
    "client_metadata": { "vp_formats_supported": { "zkp_req": {} } }
  }))
  .expect("request object")
}

#[test]
fn transcript_and_device_message_agree() {
  for file in ["decoy_test_vectors.json", "decoy_test_vectors_zero_psc.json"] {
    let v = vectors(file);
    let h = handover_of(&v);
    let ours = h.session_transcript().expect("transcript");
    assert_eq!(hex::encode(&ours), s(&v, &["sessions", "redirect", "session_transcript"]));
    let session = bsc::session(&h).expect("session");
    assert_eq!(session.transcript(), ours);
    let r = v5::Request {
      issuer_key: ([0; 32], [0; 32]),
      proof_time: "2026-10-27T12:00:00Z".into(),
      age_range: None,
      verifier_id: h.client_id.clone(),
      session,
    };
    let message = handover::device_message(&ours, "eu.europa.ec.eudi.nym_auth.1");
    assert_eq!(v5::Prover::device_signed_bytes(&r), message);
    assert_eq!(hex::encode(&message), s(&v, &["sessions", "redirect", "device_sig_structure"]));
  }
}

#[test]
fn system_id_is_the_archive_sha256() {
  assert_eq!(bsc::system_id(), format!("urn:circuits:sha256:{}", hex::encode(bsc::archive_sha256())));
  assert_eq!(bsc::system_id(), "urn:circuits:sha256:5d7d2b5d094032df5b02f576d2ae7b99d3f0932d47516336693f8d670cfd63ac");
}

#[test]
fn range_bounds_agree() {
  let ranges = ["0-0", "13-17", "16-17", "18+", "13+", "17-", "12-", "25-64", "0+", "99-"];
  let days = ["2024-02-29", "2025-02-28", "2026-01-01", "2026-03-01", "2026-10-20", "2026-10-27", "2026-12-31", "2028-02-29"];
  for r in ranges {
    for d in days {
      let (e1, c1) = dates::range_bounds(&dates::AgeRange::parse(r).unwrap(), &dates::date(d).unwrap());
      let (e2, c2) = v5::AgeRange::parse(r).unwrap().bounds(v5::Date::parse(d).unwrap());
      let n = |x: Option<dates::Date>| x.map(|x| u64::from(x.year) * 10_000 + u64::from(x.month) * 100 + u64::from(x.day));
      assert_eq!((n(e1), n(c1)), (e2.map(|x| x.yyyymmdd()), c2.map(|x| x.yyyymmdd())), "range {r} on {d}");
    }
  }
  // The vectors' own table.
  let v = vectors("decoy_test_vectors.json");
  for c in v["expected"]["range_conversion"].as_array().unwrap() {
    let (e, cc) = v5::AgeRange::parse(c["range"].as_str().unwrap()).unwrap().bounds(v5::Date::parse(c["D"].as_str().unwrap()).unwrap());
    let t = |x: Option<v5::Date>| x.map(|x| format!("{:04}-{:02}-{:02}", x.y, x.m, x.d));
    assert_eq!(t(e).as_deref(), c["E"].as_str(), "{c}");
    assert_eq!(t(cc).as_deref(), c["C"].as_str(), "{c}");
  }
}

#[test]
fn end_to_end_through_the_adapter() {
  let v = vectors("decoy_test_vectors.json");
  let h = handover_of(&v);
  let proof_time = s(&v, &["expected", "age_check", "proof_time"]);
  let d = dates::date_time(&proof_time).expect("proof_time").date;
  let ro = request_object(&h, Some("13-17"));
  statement_for(&ro, "q", &h, Rulebook::V06, Some(d)).expect("the site accepts the request");

  // The issuer key as the verifier takes it: from the Document Signer certificate.
  let signer = x509::parse(&bytes(&s(&v, &["keys", "document_signer", "cert_der"]))).expect("certificate");
  assert_eq!(hex::encode(signer.key.x), s(&v, &["keys", "document_signer", "x"]));
  let request = bsc::request(&signer.key, &proof_time, &ro, "q", &h).expect("request");

  // The device signature as Prover::sign makes it (ES256 over the device message).
  let device = SigningKey::from_bytes(&arr::<32>(&s(&v, &["keys", "device", "d"])).into()).expect("device key");
  let sig: Signature = device.sign(&v5::Prover::device_signed_bytes(&request));
  let sig: [u8; 64] = sig.to_bytes().into();

  let prover = v5::Prover::new(bsc::circuits().expect("circuits"));
  let verifier = v5::Verifier::new(bsc::circuits().expect("circuits"));
  let credential = bytes(&s(&v, &["issuer_signed_cbor"]));
  let holder = v5::Holder {
    credential: &credential,
    secret_seed: arr(&s(&v, &["holder_openings", "secret_seed"])),
    birth_date: s(&v, &["holder_openings", "birth_date"]).as_bytes().try_into().unwrap(),
  };
  // Two phases, as the wallet runs them: prebuild while consent shows, prove after the signature.
  let rng = &mut SecureRandomEngine::new();
  let pre = prover.prebuild(&request, &holder, rng).expect("prebuild");
  let p = prover.prove_prebuilt(pre, &sig, rng).expect("prove");
  assert_eq!(hex::encode(p.pseudonym), s(&v, &["expected", "pseudonyms_sha256", "known-offender-matching-ssc"]));

  // The rulebook's ZkpPresentation, as the wallet sends it and the verifier reads it.
  let wire = Presentation {
    system_id: bsc::system_id(),
    proof: p.proof.clone(),
    issuer_key_set: vec![signer.der.clone()],
    proof_time: proof_time.clone(),
    results: vec![("nym".into(), ResultValue::Pseudonym(p.pseudonym))],
  }
  .encode()
  .expect("encode");
  let read = Presentation::decode(&wire).expect("decode");
  let Some((_, ResultValue::Pseudonym(nym))) = read.results.first() else { panic!("results") };
  let got = v5::Presentation { pseudonym: *nym, proof: read.proof.clone() };
  verifier.verify(&bsc::request(&signer.key, &read.proof_time, &ro, "q", &h).unwrap(), &got).expect("verify");

  // Refusals: the verifier's own values differ from the prover's.
  let other_nonce = Handover { nonce: "another".into(), ..h.clone() };
  let ro2 = request_object(&other_nonce, Some("13-17"));
  // e2 seeds the Fiat-Shamir transcript, so another session already fails the hash proof (the
  // first one checked); `proof_invalid.input` names the first circuit that fails, not the input.
  let e = verifier.verify(&bsc::request(&signer.key, &proof_time, &ro2, "q", &other_nonce).unwrap(), &got).unwrap_err();
  assert!(bsc::failing_circuit(&e).is_some(), "{e:?}");
  // Another issuer key changes only the signature circuit's public inputs.
  let other_key = x509::PublicKey { x: arr(&s(&v, &["keys", "device", "x"])), y: arr(&s(&v, &["keys", "device", "y"])) };
  let e = verifier.verify(&bsc::request(&other_key, &proof_time, &ro, "q", &h).unwrap(), &got).unwrap_err();
  assert_eq!(bsc::failing_circuit(&e), Some("signature"), "{e:?}");
  let other_client = Handover { client_id: "x509_san_dns:other.example".into(), ..h.clone() };
  let ro3 = request_object(&other_client, Some("13-17"));
  assert!(verifier.verify(&bsc::request(&signer.key, &proof_time, &ro3, "q", &other_client).unwrap(), &got).is_err());
  let ro4 = request_object(&h, Some("18+"));
  let e = verifier.verify(&bsc::request(&signer.key, &proof_time, &ro4, "q", &h).unwrap(), &got).unwrap_err();
  assert_eq!(bsc::failing_circuit(&e), Some("hash"), "{e:?}");
  let mut tampered = got.clone();
  tampered.proof[200] ^= 1;
  assert!(verifier.verify(&request, &tampered).is_err());
  // The prover refuses a range the birth date is outside of, before proving, with its reason.
  let r18 = bsc::request(&signer.key, &proof_time, &ro4, "q", &h).unwrap();
  let e = prover.prebuild(&r18, &holder, &mut SecureRandomEngine::new()).unwrap_err();
  assert_eq!(e, v5::Error::Holder("birth_date is outside the age range"));
  assert_eq!(bsc::prover_refusal(&e).error, "unsatisfiable");
  let mut wrong_seed = holder.secret_seed;
  wrong_seed[0] ^= 1;
  let h2 = v5::Holder { credential: &credential, secret_seed: wrong_seed, birth_date: holder.birth_date };
  let e = prover.prebuild(&request, &h2, &mut SecureRandomEngine::new()).unwrap_err();
  assert_eq!(bsc::prover_refusal(&e).error, "bad_credential", "{e:?}");
}

/// The package's golden redirect presentation verifies from the values the site holds: the
/// Request Object, the handover, the Document Signer certificate and the presented proof_time.
#[test]
fn golden_presentation_from_the_site_values() {
  let p = format!("{}/../nym-auth-zk-decoy/tests/golden/redirect_13-17.json", env!("CARGO_MANIFEST_DIR"));
  let g: Value = serde_json::from_str(&std::fs::read_to_string(p).expect("golden")).expect("json");
  let r = &g["request"];
  let se = &r["session"];
  let h = Handover {
    client_id: se["client_id"].as_str().unwrap().into(),
    nonce: se["nonce"].as_str().unwrap().into(),
    response_uri: se["response_uri"].as_str().unwrap().into(),
    jwk_thumbprint: se["jwk_thumbprint"].as_str().map(|t| nym_longfellow::b64url(&bytes(t))),
  };
  let ro = request_object(&h, r["age_range"].as_str());
  let proof_time = r["proof_time"].as_str().unwrap();
  let d = dates::date_time(proof_time).expect("proof_time").date;
  statement_for(&ro, "q", &h, Rulebook::V06, Some(d)).expect("the site accepts the request");
  let signer = x509::parse(&bytes(r["issuer_cert_der"].as_str().unwrap())).expect("certificate");
  let verifier = v5::Verifier::new(bsc::circuits().expect("circuits"));
  let pr = &g["presentation"];
  let presentation = v5::Presentation {
    pseudonym: arr(pr["pseudonym"].as_str().unwrap()),
    proof: bytes(pr["proof"].as_str().unwrap()),
  };
  verifier.verify(&bsc::request(&signer.key, proof_time, &ro, "q", &h).unwrap(), &presentation).expect("verify");
}

/// The decoy credential's helper reads the Document Signer certificate and the validity, and
/// refuses a credential of the compact (IssuerSignedItem) profile.
#[test]
fn decoy_credential_helper() {
  let v = vectors("decoy_test_vectors.json");
  let c = bsc::credential(&bytes(&s(&v, &["issuer_signed_cbor"]))).expect("decoy credential");
  assert_eq!(hex::encode(&c.document_signer), s(&v, &["keys", "document_signer", "cert_der"]));
  assert_eq!(c.valid_from.text(), "2026-10-27T00:00:00Z");
  assert_eq!(c.valid_until.text(), "2027-10-27T00:00:00Z");
  let compact = std::fs::read(format!("{}/../../../profiles/nym-auth-v0.5/test-vectors/nym_auth_mdoc/issuer_signed.cbor", env!("CARGO_MANIFEST_DIR"))).unwrap();
  assert!(bsc::credential(&compact).is_err());
  let hash: usize = bsc::PUBLIC_INPUTS.iter().map(|p| p.1).sum();
  let sig: usize = bsc::PUBLIC_INPUTS.iter().map(|p| p.2).sum();
  assert_eq!((hash + 1, sig + 1), (269, 1155));
}
