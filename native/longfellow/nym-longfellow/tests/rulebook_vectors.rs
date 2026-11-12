//! Rulebook v0.5 test vectors (profiles/nym-auth-v0.5/test-vectors/nym_auth_mdoc, from the
//! nym_auth rulebook repository): the age range bounds, and the SessionTranscript and device
//! message of the redirect session (OpenID4VP 1.0 B.2.6.1), as this crate computes them.

use nym_longfellow::{dates, handover};
use serde_json::Value;

const DOC_TYPE: &str = "eu.europa.ec.eudi.nym_auth.1";

fn vectors(variant: &str) -> Value {
  let path = format!("{}/../../../profiles/nym-auth-v0.5/test-vectors/nym_auth_mdoc/nym_auth_test_vectors{variant}.json", env!("CARGO_MANIFEST_DIR"));
  serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
  (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
  b.iter().map(|x| format!("{x:02x}")).collect()
}

fn opt(d: Option<dates::Date>) -> Value {
  d.map_or(Value::Null, |d| Value::String(d.text()))
}

#[test]
fn age_ranges() {
  let v = vectors("");
  let e = &v["expected"];
  let a = &e["age_check"];
  let d = a["D"].as_str().unwrap();
  assert_eq!(&a["proof_time"].as_str().unwrap()[..10], d);
  let mut cases: Vec<(&str, &Value)> = a["cases"].as_array().unwrap().iter().map(|c| (d, c)).collect();
  cases.extend(e["range_conversion"].as_array().unwrap().iter().map(|c| (c["D"].as_str().unwrap(), c)));
  for (d, c) in cases {
    let range = c["range"].as_str().unwrap();
    let (ge, le) = dates::range_bounds(&dates::AgeRange::parse(range).unwrap(), &dates::date(d).unwrap());
    assert_eq!((opt(ge), opt(le)), (c["E"].clone(), c["C"].clone()), "{range} on {d}");
  }
}

#[test]
fn redirect_session() {
  for variant in ["", "_zero_psc"] {
    let v = vectors(variant);
    let s = &v["sessions"]["redirect"];
    let i = &s["inputs"];
    let thumbprint: [u8; 32] = unhex(i["jwk_thumbprint"].as_str().unwrap()).try_into().unwrap();
    let st = handover::session_transcript(
      i["client_id"].as_str().unwrap(),
      i["nonce"].as_str().unwrap(),
      Some(&thumbprint),
      i["response_uri"].as_str().unwrap(),
    );
    assert_eq!(hex(&st), s["session_transcript"].as_str().unwrap(), "SessionTranscript{variant}");
    assert_eq!(hex(&handover::device_message(&st, DOC_TYPE)), s["device_sig_structure"].as_str().unwrap(), "device message{variant}");
  }
}
