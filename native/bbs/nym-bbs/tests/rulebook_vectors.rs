//! Rulebook v0.5 test vectors (profiles/nym-auth-v0.5/test-vectors/nym_auth_mdoc, from the
//! nym_auth rulebook repository): the age range bounds, as this crate computes them for bbs_cd.

use nym_bbs::dates::{AgeRange, iso};
use serde_json::Value;

#[test]
fn age_ranges() {
  let path = format!("{}/../../../profiles/nym-auth-v0.5/test-vectors/nym_auth_mdoc/nym_auth_test_vectors.json", env!("CARGO_MANIFEST_DIR"));
  let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))).unwrap();
  let e = &v["expected"];
  let a = &e["age_check"];
  let d = a["D"].as_str().unwrap();
  let mut cases: Vec<(&str, &Value)> = a["cases"].as_array().unwrap().iter().map(|c| (d, c)).collect();
  cases.extend(e["range_conversion"].as_array().unwrap().iter().map(|c| (c["D"].as_str().unwrap(), c)));
  for (d, c) in cases {
    let range = c["range"].as_str().unwrap();
    let p: Vec<u32> = d.split('-').map(|x| x.parse().unwrap()).collect();
    let (ge, le) = AgeRange::parse(range).unwrap().bounds((i64::from(p[0]), p[1], p[2])).unwrap();
    let opt = |b: Option<cd_date_range::Ymd>| b.as_ref().map_or(Value::Null, |b| Value::String(iso(b)));
    assert_eq!((opt(ge), opt(le)), (c["E"].clone(), c["C"].clone()), "{range} on {d}");
  }
}
