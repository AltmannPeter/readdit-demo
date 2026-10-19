//! RFC 9380 Sections J.9.1, K.1, K.2 and K.6: independent primitive checks.

use bbs_cd::params::Ciphersuite;
use bbs_cd::primitives::{expand_message, hash_to_curve_g1};
use bls12_381::G1Affine;
use serde_json::Value;

/// RFC 9380 Appendices J and K: load only independently extracted RFC data.
fn vectors() -> Value {
    serde_json::from_str(include_str!("data/rfc9380.json")).expect("valid RFC vector JSON")
}

/// RFC 9380 Appendices J and K: decode the RFC's hexadecimal octet strings.
fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hexadecimal strings have whole octets");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).expect("ASCII hexadecimal digits");
            u8::from_str_radix(digits, 16).expect("valid hexadecimal octet")
        })
        .collect()
}

/// RFC 9380 Sections 5.3.1 and 5.3.2: check each complete expander output.
fn check_expander(section: &str, suite: Ciphersuite) {
    let data = vectors();
    let group = data["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["section"] == section)
        .expect("required RFC section");
    let dst = group["DST"].as_str().unwrap().as_bytes();
    let cases = group["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 10, "all vectors in RFC section {section}");
    for (index, case) in cases.iter().enumerate() {
        let msg = case["msg"].as_str().unwrap().as_bytes();
        let len = usize::try_from(case["len_in_bytes"].as_u64().unwrap()).unwrap();
        let expected = decode_hex(case["uniform_bytes"].as_str().unwrap());
        let actual = expand_message(suite, msg, dst, len)
            .unwrap_or_else(|error| panic!("RFC {section} vector {index} aborted: {error:?}"));
        assert_eq!(actual, expected, "RFC {section} vector {index}");
    }
}

/// RFC 9380 Section K.1: all ten SHA-256 XMD ordinary-DST vectors.
#[test]
fn sha256_xmd_vectors() {
    check_expander("K.1", Ciphersuite::Sha256);
}

/// RFC 9380 Section K.2: all ten SHA-256 XMD oversized-DST vectors.
#[test]
fn sha256_xmd_long_dst_vectors() {
    check_expander("K.2", Ciphersuite::Sha256);
}

/// RFC 9380 Section K.6: all ten SHAKE-256 XOF ordinary-DST vectors.
///
/// These k=256 vectors have a short DST, making the outputs also applicable
/// to BBS's k=128 expander; Section 5.3.3's k-dependent DST hash is unused.
#[test]
fn shake256_xof_vectors() {
    let data = vectors();
    let group = data["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["section"] == "K.6")
        .unwrap();
    assert_eq!(group["k"], 256);
    assert!(group["DST"].as_str().unwrap().len() <= 255);
    check_expander("K.6", Ciphersuite::Shake256);
}

/// RFC 9380 Section J.9.1: all five BLS12-381 G1 SHA-256 random-oracle vectors.
#[test]
fn bls12381g1_sha256_hash_to_curve_vectors() {
    let data = vectors();
    let group = data["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["section"] == "J.9.1")
        .unwrap();
    let dst = group["dst"].as_str().unwrap().as_bytes();
    let cases = group["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5, "all vectors in RFC section J.9.1");
    for (index, case) in cases.iter().enumerate() {
        let msg = case["msg"].as_str().unwrap().as_bytes();
        let point = hash_to_curve_g1(Ciphersuite::Sha256, msg, dst)
            .unwrap_or_else(|error| panic!("RFC J.9.1 vector {index} aborted: {error:?}"));
        let actual = G1Affine::from(point).to_uncompressed();
        let expected_x = decode_hex(case["P.x"].as_str().unwrap());
        let expected_y = decode_hex(case["P.y"].as_str().unwrap());
        assert_eq!(&actual[..48], expected_x, "RFC J.9.1 vector {index} P.x");
        assert_eq!(&actual[48..], expected_y, "RFC J.9.1 vector {index} P.y");
    }
}
