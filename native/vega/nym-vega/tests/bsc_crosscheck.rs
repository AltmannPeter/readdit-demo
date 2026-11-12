//! The rulebook v0.5 Vega circuits (`vega_age::bsc`) through Community's own values, on the
//! rulebook v0.5 test vectors (`profiles/nym-auth-v0.5/test-vectors/nym_auth_mdoc`).
//! SHIPPED WITH THE CIRCUIT PACKAGE: drop into `native/vega/nym-vega/tests/`.
//!
//! 1. The circuits as data: `circuits/mdoc-bsc/shapes.zst` is the shipped file, and its id.
//! 2. End to end through `bsc.rs`: the credential taken apart by `mdoc::parse`, the issuer key from
//!    its Document Signer certificate, the Request Object and handover as the site holds them, the
//!    device signature as `Prover::sign` makes it; witness, prove, ZkpPresentation encode and
//!    decode, accept; and each refusal names its public input.
//! 3. The package's golden proof verifies from the site's values.

use nym_vega::handover::{self, Handover};
use nym_vega::presentation::{Presentation, ResultValue};
use nym_vega::request::{RequestObject, Rulebook, statement_for};
use nym_vega::{bsc, dates, mdoc, x509};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value, json};
use vega_age::app;

const SHAPES_SHA256: &str = "7df07fefef643512270e2de4964bc1f9b6238015225cfd872e2fb35e7bb80794";

fn vectors() -> Value {
  let p = format!(
    "{}/../../../profiles/nym-auth-v0.5/test-vectors/nym_auth_mdoc/nym_auth_test_vectors.json",
    env!("CARGO_MANIFEST_DIR")
  );
  serde_json::from_str(&std::fs::read_to_string(p).expect("vectors")).expect("json")
}

fn shapes() -> Vec<u8> {
  std::fs::read(format!("{}/../circuits/mdoc-bsc/shapes.zst", env!("CARGO_MANIFEST_DIR")))
    .expect("shapes.zst")
}

fn s(v: &Value, path: &[&str]) -> String {
  path
    .iter()
    .fold(v, |x, k| &x[*k])
    .as_str()
    .unwrap_or_else(|| panic!("{}", path.join(".")))
    .to_string()
}

fn bytes(h: &str) -> Vec<u8> {
  hex::decode(h).expect("hex")
}

fn handover_of(v: &Value) -> Handover {
  let i = &v["sessions"]["redirect"]["inputs"];
  Handover {
    client_id: i["client_id"].as_str().unwrap().into(),
    nonce: i["nonce"].as_str().unwrap().into(),
    response_uri: i["response_uri"].as_str().unwrap().into(),
    jwk_thumbprint: i["jwk_thumbprint"].as_str().map(|t| nym_vega::b64url(&bytes(t))),
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
fn the_shipped_circuits_and_their_id() {
  let zst = shapes();
  assert_eq!(bsc::system_id(&zst), format!("urn:circuits:sha256:{SHAPES_SHA256}"));
  // The file decompresses to the circuits vega-age builds.
  let raw = zstd::stream::decode_all(&zst[..]).unwrap();
  assert!(raw == app::shapes(&vega_age::bsc::BscCore::blank()).unwrap());
  assert_eq!(bsc::PUBLIC_INPUTS.iter().map(|p| p.1).sum::<usize>(), 15);
}

#[test]
fn end_to_end_through_the_adapter() {
  let v = vectors();
  let h = handover_of(&v);
  let proof_time = s(&v, &["expected", "age_check", "proof_time"]);
  let t = dates::date_time(&proof_time).unwrap();
  let ro = request_object(&h, Some("13-17"));
  let st =
    statement_for(&ro, "q", &h, Rulebook::V05, Some(t.date)).expect("the site accepts the request");

  // The holder's side.
  let m =
    mdoc::parse(&nym_vega::b64url(&bytes(&s(&v, &["issuer_signed_cbor"])))).expect("IssuerSigned");
  let signer = x509::parse(&m.document_signer).expect("certificate");
  assert_eq!(hex::encode(signer.key.x), s(&v, &["keys", "document_signer", "x"]));
  let seed: [u8; 16] = bytes(&s(&v, &["holder_openings", "secret_seed"])).try_into().unwrap();
  let birth: [u8; 10] = s(&v, &["holder_openings", "birth_date"]).as_bytes().try_into().unwrap();
  assert_eq!(bsc::commitment(&seed, &birth).to_vec(), bytes(&s(&v, &["commitments", "bsc"])));
  let device =
    SigningKey::from_bytes(bytes(&s(&v, &["keys", "device", "d"])).as_slice().into()).unwrap();
  let message = handover::device_message(&st.session_transcript, "eu.europa.ec.eudi.nym_auth.1");
  let sig: Signature = device.sign(&message);
  let sig: [u8; 64] = sig.to_bytes().into();
  let nym = bsc::pseudonym_for(&seed, &st);
  assert_eq!(
    hex::encode(nym),
    s(&v, &["expected", "pseudonyms_sha256", "known-offender-matching-ssc"])
  );

  let zst = shapes();
  let (pk, vk) = bsc::keys(&zst).unwrap();
  let w = bsc::witness(&m, signer.key, &seed, &birth, &st).expect("witness");
  let core = bsc::core(w.clone(), bsc::public(signer.key, &st, t, nym).unwrap(), &sig);
  let steps = app::steps(&w.table);
  let a = app::witness(&steps, &core).unwrap();
  let prepared = app::prepare(&pk, &a.steps(), &a.core()).unwrap();
  let (proof, _) = app::prove(&pk, &a.steps(), &a.core(), prepared).unwrap();
  let wire = Presentation {
    system_id: bsc::system_id(&zst),
    proof: bincode::serialize(&proof).unwrap(),
    issuer_key_set: vec![m.document_signer.clone()],
    proof_time: proof_time.clone(),
    results: vec![("nym".into(), ResultValue::Pseudonym(nym))],
  }
  .encode()
  .unwrap();

  // The verifier's side: everything from its own values but issuer_key_set, proof_time, results.
  let p = Presentation::decode(&wire).unwrap();
  let Some((_, ResultValue::Pseudonym(presented))) = p.results.first() else { panic!("results") };
  let proof: app::Proof = bincode::deserialize(&p.proof).unwrap();
  let key = x509::parse(&p.issuer_key_set[0]).unwrap().key;
  let pt = dates::date_time(&p.proof_time).unwrap();
  let check = |st: &nym_vega::request::Statement, key, pt, nym| {
    bsc::accept(&vk, &proof, &bsc::public(key, st, pt, nym).unwrap())
  };
  assert_eq!(check(&st, key, pt, *presented), Ok(nym));

  // Refusals, each naming its input.
  let other_nonce = Handover { nonce: "another".into(), ..h.clone() };
  let st2 = statement_for(
    &request_object(&other_nonce, Some("13-17")),
    "q",
    &other_nonce,
    Rulebook::V05,
    Some(t.date),
  )
  .unwrap();
  assert_eq!(check(&st2, key, pt, nym), Err(("public_input", Some("session_transcript"))));
  let st3 =
    statement_for(&request_object(&h, Some("18+")), "q", &h, Rulebook::V05, Some(t.date)).unwrap();
  assert_eq!(check(&st3, key, pt, nym), Err(("public_input", Some("age_check.ge"))));
  let other_client = Handover { client_id: "x509_san_dns:other.example".into(), ..h.clone() };
  let st4 = statement_for(
    &request_object(&other_client, Some("13-17")),
    "q",
    &other_client,
    Rulebook::V05,
    Some(t.date),
  )
  .unwrap();
  assert!(matches!(check(&st4, key, pt, nym), Err(("public_input", Some(_)))));
  let later = dates::from_unix(dates::unix(&pt).unwrap() + 1).unwrap();
  assert_eq!(check(&st, key, later, nym), Err(("public_input", Some("proof_time"))));
  let other_key = vega_age::gadgets::p256::PublicKey { x: m.device_key.x, y: m.device_key.y };
  assert_eq!(check(&st, other_key, pt, nym), Err(("public_input", Some("issuer_key_set"))));
  let mut flipped = nym;
  flipped[0] ^= 1;
  assert_eq!(check(&st, key, pt, flipped), Err(("public_input", Some("results.nym"))));
}

#[test]
fn golden_proof_from_the_site_values() {
  let p =
    format!("{}/../vega-age/tests/golden/bsc_redirect_13-17.json", env!("CARGO_MANIFEST_DIR"));
  let g: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
  let v = vectors();
  let h = handover_of(&v);
  assert_eq!(h.client_id, s(&g, &["verifier_id"]));
  let t = dates::date_time(&s(&g, &["proof_time"])).unwrap();
  let st = statement_for(&request_object(&h, Some("13-17")), "q", &h, Rulebook::V05, Some(t.date))
    .unwrap();
  assert_eq!(hex::encode(st.challenge), s(&g, &["challenge"]));
  let key = vega_age::gadgets::p256::PublicKey {
    x: bytes(&s(&g, &["issuer_key", "x"])).try_into().unwrap(),
    y: bytes(&s(&g, &["issuer_key", "y"])).try_into().unwrap(),
  };
  let nym: [u8; 32] = bytes(&s(&g, &["pseudonym"])).try_into().unwrap();
  let (_, vk) = bsc::keys(&shapes()).unwrap();
  let proof: app::Proof = bincode::deserialize(&bytes(&s(&g, &["proof"]))).unwrap();
  assert_eq!(bsc::accept(&vk, &proof, &bsc::public(key, &st, t, nym).unwrap()), Ok(nym));
}
