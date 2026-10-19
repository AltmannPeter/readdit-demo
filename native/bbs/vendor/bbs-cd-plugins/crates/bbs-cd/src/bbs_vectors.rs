//! BBS-12 cross-checks against the BBS-13 vector text (IMPLEMENTERS.md 10).
//! This test module never exercises the profile's deliberately different proof transcript.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    fs,
    path::{Path, PathBuf},
};

use bls12_381::Scalar;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::core::{CoreSign, CoreVerify, ProofInit};
use crate::interface::{KeyGen, SkToPk};
use crate::mock_rng::seeded_random_scalars;
use crate::params::Ciphersuite;
use crate::primitives::point_to_octets_E1;
use crate::types::{Index, Message, MessageType, ScalarInput};
use crate::utils::{
    calculate_domain, create_generators, hash_to_scalar, messages_to_scalars, octets_to_signature,
};
use crate::{BbsError, BbsResult};

type Check = Result<(), String>;
const SOURCE_FILE: &str = "draft-irtf-cfrg-bbs-signatures-13.txt";
const SOURCE_SHA256: &str = "78b71f9a4bcdf57fbce694b015ed22bcf5b71ff5263b8f8d57ae2bbcf6514cd2";

/// BBS-12 8 and Appendix D. Resolve only this Rust repository's vector directory.
fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/bbs")
}

/// BBS-12 8 and Appendix D. Parse fixture JSON without mapping parse failures to INVALID.
fn read_json(path: &Path) -> Result<Value, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))
}

/// BBS-12 8 and Appendix D. Require a JSON string at a named field.
fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string {field}"))
}

/// BBS-12 8 and Appendix D. Require a JSON array at a named field.
fn array<'a>(value: &'a Value, field: &str) -> Result<&'a [Value], String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("missing array {field}"))
}

/// Spec 1.4.2. Decode lowercase hexadecimal fixture octets with no coercion.
fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!("invalid lowercase hexadecimal {value:?}"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).map_err(|e| e.to_string())?, 16)
                .map_err(|e| e.to_string())
        })
        .collect()
}

/// Spec 1.4.2. Encode actual values for precise fixture mismatch diagnostics.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::new();
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

/// BBS-12 8 and Appendix D. Read a hex field as octets.
fn bytes(value: &Value, field: &str) -> Result<Vec<u8>, String> {
    decode_hex(string(value, field)?)
}

/// Spec 1.4.3. Preserve fixture scalar input before validating it in the operation.
fn scalar(value: &str) -> Result<ScalarInput, String> {
    Ok(ScalarInput(
        decode_hex(value)?
            .try_into()
            .map_err(|_| "scalar is not 32 octets")?,
    ))
}

/// BBS-12 8 and Appendix D. Surface operation errors separately from parse failures.
fn operation<T>(field: &str, result: BbsResult<T>) -> Result<T, String> {
    result.map_err(|error| format!("{field}: unexpected {error}"))
}

/// IMPLEMENTERS.md 11. Stop a case at the first differing checked trace field.
fn equal<T: Debug + PartialEq + ?Sized>(field: &str, actual: &T, expected: &T) -> Check {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "first divergence {field}: expected {expected:?}; actual {actual:?}"
        ))
    }
}

/// BBS-12 8.3.2/8.4.2. Match messages by their values, never draft variable names.
fn mapped_messages(
    suite: Ciphersuite,
    input: &Value,
    reference: &Value,
) -> Result<Vec<ScalarInput>, String> {
    let messages: Vec<Message> = array(input, "messages")?
        .iter()
        .map(|v| {
            Ok(Message::Octets(decode_hex(
                v.as_str().ok_or("message is not octets")?,
            )?))
        })
        .collect::<Result<_, String>>()?;
    let types = vec![MessageType::OCTETS; messages.len()];
    let actual = operation(
        "messageScalars",
        messages_to_scalars(suite, &messages, &types, &suite.bbs_api_id()),
    )?;
    let known_messages = array(reference, "messages")?;
    let known_scalars = array(reference, "scalars")?;
    for (index, message) in array(input, "messages")?.iter().enumerate() {
        let position = known_messages
            .iter()
            .position(|known| known == message)
            .ok_or_else(|| format!("unknown message value at {index}"))?;
        let expected = string_at(known_scalars, position)?;
        equal(
            &format!("messageScalars[{index}]"),
            &hex(&actual[index].0),
            expected,
        )?;
    }
    // References are informational, but incorrect extraction metadata is an error.
    if let Some(references) = input.get("messageRefs8_2") {
        let references = references
            .as_array()
            .ok_or("messageRefs8_2 is not an array")?;
        equal("messageRefs8_2.length", &references.len(), &messages.len())?;
        for (index, reference) in references.iter().enumerate() {
            let reference = reference
                .as_u64()
                .ok_or("message reference is not an integer")? as usize;
            equal(
                "messageRefs8_2.value",
                &array(input, "messages")?[index],
                known_messages
                    .get(reference)
                    .ok_or("message reference out of bounds")?,
            )?;
        }
    }
    Ok(actual)
}

/// BBS-12 8.3.2/8.4.2. Read one expected hexadecimal scalar string.
fn string_at(values: &[Value], index: usize) -> Result<&String, String> {
    match values.get(index) {
        Some(Value::String(value)) => Ok(value),
        _ => Err(format!("missing string at array index {index}")),
    }
}

/// Spec 3.6.1; BBS-12 8.3.4/8.4.4. Compare domain before the B trace point.
fn signature_case(suite: Ciphersuite, value: &Value, reference: &Value) -> Check {
    equal("operation", string(value, "operation")?, "Verify")?;
    let valid = value["expected"]["result"]["valid"]
        .as_bool()
        .ok_or("missing expected valid boolean")?;
    let trace = value["trace"].as_object().ok_or("trace is not an object")?;
    let input = &value["input"];
    let messages = mapped_messages(suite, input, reference)?;
    let PK = bytes(input, "PK")?;
    let header = bytes(input, "header")?;
    let api_id = suite.bbs_api_id();
    let generators = operation(
        "generators",
        create_generators(suite, messages.len() as u128 + 1, &api_id),
    )?;
    let domain = operation(
        "domain",
        calculate_domain(
            suite,
            &PK,
            &generators[0],
            &generators[1..],
            &header,
            &api_id,
        ),
    )?;
    if valid || trace.contains_key("domain") {
        let expected = string(&value["trace"], "domain")?;
        equal("domain", hex(&domain.0).as_str(), expected)?;
    }
    if valid || trace.contains_key("B") {
        let expected = string(&value["trace"], "B")?;
        let mut B = suite.P1() + generators[0] * operation("domain", domain.to_scalar())?;
        for (H, message) in generators[1..].iter().zip(&messages) {
            B += H * operation("message scalar", message.to_scalar())?;
        }
        equal("B", hex(&point_to_octets_E1(&B)).as_str(), expected)?;
    }
    let signature = bytes(input, "signature")?;
    let verified = CoreVerify(
        suite,
        &PK,
        &signature,
        &generators,
        &header,
        &messages,
        &api_id,
    );
    equal(
        "CoreVerify",
        &verified,
        &if valid {
            Ok(())
        } else {
            Err(BbsError::Invalid)
        },
    )?;
    if valid {
        let SK = scalar(string(input, "SK")?)?;
        let signed = operation(
            "CoreSign",
            CoreSign(suite, SK, &PK, &generators, &header, &messages, &api_id),
        )?;
        equal("signature", &hex(&signed), &hex(&signature))?;
    }
    Ok(())
}

/// Spec 3.7.1; BBS-12 8.3.5/8.4.5 and D.x.2. Compare only shared initialization.
fn proof_case(suite: Ciphersuite, value: &Value, reference: &Value) -> Check {
    equal("operation", string(value, "operation")?, "ProofGen")?;
    let input = &value["input"];
    let messages = mapped_messages(suite, input, reference)?;
    let revealed: BTreeSet<u64> = array(input, "revealedIndexes")?
        .iter()
        .map(|v| {
            v.as_u64()
                .ok_or_else(|| "noninteger revealed index".to_owned())
        })
        .collect::<Result<_, _>>()?;
    equal(
        "revealedIndexes uniqueness",
        &revealed.len(),
        &array(input, "revealedIndexes")?.len(),
    )?;
    if revealed.iter().any(|i| *i >= messages.len() as u64) {
        return Err("revealed index out of bounds".into());
    }
    let undisclosed: Vec<Index> = (0..messages.len() as u64)
        .filter(|i| !revealed.contains(i))
        .map(Index::from)
        .collect();
    let mocked = &value["mockedRng"];
    let random = operation(
        "randomScalars",
        seeded_random_scalars(
            suite,
            &bytes(mocked, "seed")?,
            &bytes(mocked, "dst")?,
            5 + undisclosed.len(),
        ),
    )?;
    let api_id = suite.bbs_api_id();
    let generators = operation(
        "generators",
        create_generators(suite, messages.len() as u128 + 1, &api_id),
    )?;
    let signature = operation(
        "signature",
        octets_to_signature(&bytes(input, "signature")?),
    )?;
    let init = operation(
        "ProofInit",
        ProofInit(
            suite,
            &bytes(input, "PK")?,
            &signature,
            &generators,
            &random,
            &bytes(input, "header")?,
            &messages,
            &undisclosed,
            &[],
            &[],
            &api_id,
        ),
    )?;
    equal(
        "domain",
        hex(&init.domain.0).as_str(),
        string(&value["trace"], "domain")?,
    )?;
    equal("C_tildes.length", &init.C_tildes.len(), &0)?;
    let proof = bytes(&value["expected"], "output")?;
    if proof.len() < 144 {
        return Err("BBS proof shorter than its three-point prefix".into());
    }
    for (field, actual, expected) in [
        ("A_bar", init.A_bar, &proof[..48]),
        ("B_bar", init.B_bar, &proof[48..96]),
        ("D", init.D, &proof[96..144]),
    ] {
        equal(field, &hex(&point_to_octets_E1(&actual)), &hex(expected))?;
    }
    for (field, point) in [("T1", init.T1), ("T2", init.T2)] {
        if let Some(expected) = value["trace"][field].as_str() {
            equal(field, hex(&point_to_octets_E1(&point)).as_str(), expected)?;
        } else if string(value, "source")? != "D.2.2.1" {
            return Err(format!("unexpected missing {field}"));
        } else if !value["trace"][field].is_null() {
            return Err(format!("malformed {field}"));
        }
    }
    if let Some(expected) = value["trace"]["randomScalars"].as_array() {
        equal("randomScalars.length", &random.len(), &expected.len())?;
        for (i, actual) in random.iter().enumerate() {
            equal(
                &format!("randomScalars[{i}]"),
                &hex(&actual.0),
                string_at(expected, i)?,
            )?;
        }
    } else if !string(value, "source")?.starts_with("D.")
        || !value["trace"]["randomScalars"].is_null()
    {
        return Err("unexpected missing randomScalars".into());
    }
    // The supplied draft cases do not list r3, but compare it if supplied.
    if value["trace"].get("r3").is_some() {
        let expected = string(&value["trace"], "r3")?;
        let r2 = operation("r2", random[1].to_scalar())?;
        let r3 = Option::<Scalar>::from(r2.invert()).ok_or("r2 is zero")?;
        equal("r3", hex(&ScalarInput::from(r3).0).as_str(), expected)?;
    }
    Ok(())
}

/// BBS-12 8.3/8.4 and Appendix D. Build the exact expected source-section inventory.
fn inventory(prefix: &str, appendix: &str) -> BTreeMap<String, String> {
    let mut expected = BTreeMap::new();
    for (file, suffix) in [
        ("keypair.json", "1"),
        ("map_messages_to_scalars.json", "2"),
        ("generators.json", "3"),
        ("mocked_random_scalars.json", "5"),
    ] {
        expected.insert(file.into(), format!("{prefix}.{suffix}"));
    }
    expected.insert("hash_to_scalar.json".into(), format!("{appendix}.3"));
    for (index, name) in [
        "valid_single_message_signature",
        "valid_multi_message_signature",
        "no_header_valid_signature",
        "modified_message_signature",
        "extra_unsigned_message_signature",
        "missing_message_signature",
        "reordered_message_signature",
        "wrong_public_key_signature",
        "wrong_header_signature",
    ]
    .iter()
    .enumerate()
    {
        let n = index + 1;
        expected.insert(
            format!("signature/{n:03}_{name}.json"),
            if n <= 2 {
                format!("{prefix}.4.{n}")
            } else {
                format!("{appendix}.1.{}", n - 2)
            },
        );
    }
    for (index, name) in [
        "valid_single_message_proof",
        "valid_multi_message_all_messages_disclosed_proof",
        "valid_multi_message_some_messages_disclosed_proof",
        "no_header_valid_proof",
        "no_presentation_header_valid_proof",
    ]
    .iter()
    .enumerate()
    {
        let n = index + 1;
        expected.insert(
            format!("proof/{n:03}_{name}.json"),
            if n <= 3 {
                format!("{prefix}.5.{n}")
            } else {
                format!("{appendix}.2.{}", n - 3)
            },
        );
    }
    expected
}

/// BBS-12 8 and Appendix D. Enumerate JSON cases recursively, detecting extra files.
fn json_files(root: &Path, path: &Path, output: &mut BTreeSet<String>) -> Result<(), String> {
    for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            json_files(root, &path, output)?;
        } else if path.extension().is_some_and(|e| e == "json") {
            output.insert(
                path.strip_prefix(root)
                    .map_err(|e| e.to_string())?
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
    Ok(())
}

/// IMPLEMENTERS.md 11. Preserve a case's first mismatch or parsing/operation error.
fn case_report(path: &Path, source: &str, category: &str, result: &Check) -> Value {
    let mut report = json!({
        "path": path.strip_prefix(env!("CARGO_MANIFEST_DIR")).unwrap_or(path).to_string_lossy(),
        "source": source,
        "operation": category,
        "status": if result.is_ok() { "pass" } else { "fail" },
    });
    if let Err(error) = result {
        report["error"] = json!(error);
        if let Some(divergence) = error.strip_prefix("first divergence ") {
            report["firstDivergence"] = json!(divergence.split(": expected ").next().unwrap());
        }
    }
    // IMPLEMENTERS.md 10: this draft source omits both trace points.
    if source == "D.2.2.1" {
        report["exceptions"] = json!([{
            "fields": ["T1", "T2"],
            "reason": "BBS draft D.2.2.1 omits these source trace values; all other shared ProofInit checks apply"
        }]);
    }
    report
}

/// IMPLEMENTERS.md 11. Check a complete suite without aborting before report creation.
fn suite_report(
    suite: Ciphersuite,
    name: &str,
    prefix: &str,
    appendix: &str,
    fixture_directory: &Path,
) -> Value {
    let root = fixture_directory.join(name);
    let expected = inventory(prefix, appendix);
    let reference = (|| -> Result<Value, String> {
        let mut actual = BTreeSet::new();
        json_files(&root, &root, &mut actual)?;
        equal(
            "suite inventory",
            &actual,
            &expected.keys().cloned().collect(),
        )?;
        equal("expected case count", &expected.len(), &19)?;
        let reference = read_json(&root.join("map_messages_to_scalars.json"))?;
        let shared = read_json(&fixture_directory.join("messages.json"))?;
        equal("shared source", string(&shared, "source")?, "8.2")?;
        equal(
            "shared messages",
            array(&reference, "messages")?,
            array(&shared, "messages")?,
        )?;
        equal(
            "shared message count",
            &array(&reference, "messages")?.len(),
            &10,
        )?;
        equal(
            "reference scalar count",
            &array(&reference, "scalars")?.len(),
            &10,
        )?;
        Ok(reference)
    })();
    let errors: Vec<_> = reference.as_ref().err().cloned().into_iter().collect();
    let mut counts: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    let mut cases = Vec::new();
    for (file, source) in expected {
        let path = root.join(&file);
        let category = if file.starts_with("signature/") {
            "Signature"
        } else if file.starts_with("proof/") {
            "ProofInit"
        } else {
            match file.as_str() {
                "keypair.json" => "KeyPair",
                "map_messages_to_scalars.json" => "MessagesToScalars",
                "generators.json" => "CreateGenerators",
                "hash_to_scalar.json" => "HashToScalar",
                "mocked_random_scalars.json" => "SeededRandomScalars",
                _ => unreachable!(),
            }
        };
        let result = (|| -> Check {
            let reference = reference
                .as_ref()
                .map_err(|error| format!("suite setup: {error}"))?;
            let v = read_json(&path)?;
            equal("source", string(&v, "source")?, source.as_str())?;
            equal("ciphersuite", string(&v, "ciphersuite")?, name)?;
            match category {
                "KeyPair" => {
                    let SK = operation(
                        "SK",
                        KeyGen(
                            suite,
                            &bytes(&v, "keyMaterial")?,
                            &bytes(&v, "keyInfo")?,
                            Some(&bytes(&v, "keyDst")?),
                        ),
                    )?;
                    equal("SK", hex(&SK.0).as_str(), string(&v, "SK")?)?;
                    equal(
                        "PK",
                        hex(&operation("PK", SkToPk(SK))?).as_str(),
                        string(&v, "PK")?,
                    )?;
                }
                "MessagesToScalars" => {
                    equal("message count", &array(&v, "messages")?.len(), &10)?;
                    equal("scalar count", &array(&v, "scalars")?.len(), &10)?;
                    mapped_messages(suite, &v, &v)?;
                }
                "CreateGenerators" => {
                    equal("generator count", &v["count"], &Value::from(11))?;
                    let generators = operation(
                        "generators",
                        create_generators(suite, 11, &suite.bbs_api_id()),
                    )?;
                    let expected = array(&v, "generators")?;
                    equal("generators.length", &expected.len(), &11)?;
                    for (i, generator) in generators.iter().enumerate() {
                        equal(
                            &format!("generators[{i}]"),
                            &hex(&point_to_octets_E1(generator)),
                            string_at(expected, i)?,
                        )?;
                    }
                }
                "HashToScalar" => {
                    let actual = operation(
                        "hashToScalar",
                        hash_to_scalar(suite, &bytes(&v, "msg")?, &bytes(&v, "dst")?),
                    )?;
                    equal("scalar", hex(&actual.0).as_str(), string(&v, "scalar")?)?;
                }
                "SeededRandomScalars" => {
                    equal("mock count", &v["count"], &Value::from(10))?;
                    let actual = operation(
                        "seededRandomScalars",
                        seeded_random_scalars(suite, &bytes(&v, "seed")?, &bytes(&v, "dst")?, 10),
                    )?;
                    let expected = array(&v, "scalars")?;
                    equal("randomScalars.length", &expected.len(), &10)?;
                    for (i, value) in actual.iter().enumerate() {
                        equal(
                            &format!("randomScalars[{i}]"),
                            &hex(&value.0),
                            string_at(expected, i)?,
                        )?;
                    }
                }
                "Signature" => signature_case(suite, &v, reference)?,
                "ProofInit" => proof_case(suite, &v, reference)?,
                _ => return Err(format!("unhandled category {category}")),
            }
            Ok(())
        })();
        cases.push(case_report(&path, &source, category, &result));
        let count = counts.entry(category).or_default();
        match result {
            Ok(()) => count.0 += 1,
            Err(_) => count.1 += 1,
        }
    }
    let passed: usize = counts.values().map(|count| count.0).sum();
    let failed: usize = counts.values().map(|count| count.1).sum();
    let operations: BTreeMap<_, _> = counts
        .iter()
        .map(|(operation, (pass, fail))| (*operation, json!({"passed": pass, "failed": fail})))
        .collect();
    json!({
        "baseline": "BBS-12",
        "suite": name,
        "fixtureSet": "bbs",
        "countUnit": "fixture cases; KeyPair checks KeyGen and SkToPk; Signature checks Verify and exact re-signing of valid cases; ProofInit checks shared initialization only",
        "passed": passed,
        "failed": failed,
        "operations": operations,
        "cases": cases,
        "errors": errors,
        "parseFailureToInvalidMappings": [],
    })
}

/// IMPLEMENTERS.md 11. Persist reports in the caller-created directory before asserting.
fn write_report(directory: &Path, name: &str, report: &Value) -> Check {
    let path = directory.join(name);
    let mut bytes = serde_json::to_vec_pretty(report).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    fs::write(&path, bytes).map_err(|error| format!("write {}: {error}", path.display()))
}

/// BBS-12 8.3/8.4 and Appendix D. Retain the exact 19-case suite success criteria.
fn suite(suite: Ciphersuite, name: &str, prefix: &str, appendix: &str) {
    let report = suite_report(suite, name, prefix, appendix, &fixture_root());
    for case in report["cases"].as_array().unwrap() {
        println!(
            "{} {} {}{}",
            if case["status"] == "pass" {
                "PASS"
            } else {
                "FAIL"
            },
            case["source"].as_str().unwrap(),
            case["path"].as_str().unwrap(),
            case.get("error")
                .and_then(Value::as_str)
                .map(|e| format!(": {e}"))
                .unwrap_or_default()
        );
    }
    for (category, counts) in report["operations"].as_object().unwrap() {
        println!(
            "SUMMARY {name} {category}: {} passed, {} failed",
            counts["passed"], counts["failed"]
        );
    }
    println!("SUMMARY {name}: 19 vector cases; parse-failure-to-INVALID mappings: 0");
    if let Some(directory) = std::env::var_os("BBS_REPORT_DIR") {
        let filename = match suite {
            Ciphersuite::Sha256 => "bbs-sha256.json",
            Ciphersuite::Shake256 => "bbs-shake256.json",
        };
        write_report(Path::new(&directory), filename, &report).unwrap();
    }
    assert_eq!(report["cases"].as_array().unwrap().len(), 19);
    assert_eq!(report["operations"].as_object().unwrap().len(), 7);
    for (operation, total) in [("Signature", 9), ("ProofInit", 5)] {
        let counts = &report["operations"][operation];
        assert_eq!(
            counts["passed"].as_u64().unwrap() + counts["failed"].as_u64().unwrap(),
            total
        );
    }
    assert_eq!(report["failed"], 0, "{report:#}");
    assert!(
        report["errors"].as_array().unwrap().is_empty(),
        "{report:#}"
    );
}

/// IMPLEMENTERS.md 11. Reports distinguish successful cases, mismatches, and source gaps.
#[test]
fn case_report_preserves_failure_and_source_exception() {
    let path = Path::new("fixture.json");
    let success = case_report(path, "8.4.1", "KeyPair", &Ok(()));
    assert_eq!(success["status"], "pass");
    assert!(success.get("error").is_none());
    assert!(success.get("exceptions").is_none());
    let error = equal("domain", &"actual", &"expected");
    let failure = case_report(path, "D.2.2.1", "ProofInit", &error);
    assert_eq!(failure["status"], "fail");
    assert_eq!(failure["firstDivergence"], "domain");
    assert!(failure["error"].as_str().unwrap().contains("expected"));
    assert!(failure["error"].as_str().unwrap().contains("actual"));
    assert_eq!(failure["exceptions"][0]["fields"], json!(["T1", "T2"]));
    let parse = case_report(path, "8.4.1", "KeyPair", &Err("malformed fixture".into()));
    assert_eq!(parse["error"], "malformed fixture");
    assert!(parse.get("firstDivergence").is_none());
}

/// IMPLEMENTERS.md 11. Malformed inventory remains a failed, persisted 19-case report.
#[test]
fn malformed_inventory_report_is_persisted() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("bbs-report-{}-{unique}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    fs::create_dir(directory.join("BLS12-381-SHA-256")).unwrap();
    let report = suite_report(
        Ciphersuite::Sha256,
        "BLS12-381-SHA-256",
        "8.4",
        "D.2",
        &directory,
    );
    write_report(&directory, "bbs-sha256.json", &report).unwrap();
    let persisted = read_json(&directory.join("bbs-sha256.json")).unwrap();
    assert_eq!(persisted, report);
    assert_eq!(persisted["baseline"], "BBS-12");
    assert_eq!(persisted["passed"], 0);
    assert_eq!(persisted["failed"], 19);
    assert_eq!(persisted["cases"].as_array().unwrap().len(), 19);
    assert_eq!(persisted["operations"]["Signature"]["failed"], 9);
    assert_eq!(persisted["operations"]["ProofInit"]["failed"], 5);
    assert!(
        persisted["errors"][0]
            .as_str()
            .unwrap()
            .contains("suite inventory")
    );
    assert!(persisted["cases"].as_array().unwrap().iter().all(|case| {
        case["status"] == "fail" && case["error"].as_str().unwrap().contains("suite setup")
    }));
    fs::remove_dir_all(directory).unwrap();
}

/// BBS-13 SOURCE.md. Bind extracted vectors to the immutable published source text.
#[test]
fn provenance_and_global_inventory() {
    let root = fixture_root();
    let manifest = fs::read_to_string(root.join("SOURCE.md")).unwrap();
    assert!(manifest.contains(SOURCE_FILE));
    assert!(manifest.contains(SOURCE_SHA256));
    let source = fs::read(root.join("source").join(SOURCE_FILE)).unwrap();
    assert_eq!(hex(&Sha256::digest(source)), SOURCE_SHA256);
    let mut json = BTreeSet::new();
    json_files(&root, &root, &mut json).unwrap();
    assert_eq!(
        json.len(),
        39,
        "one shared input set and 19 cases per suite"
    );
    assert!(json.contains("messages.json"));
    println!("PASS provenance {SOURCE_FILE} SHA256={SOURCE_SHA256}; 39 JSON files");
}

/// BBS-12 8.4 and D.2. Full applicable SHA-256 vector cross-check.
#[test]
fn sha256_all_bbs_vectors() {
    suite(Ciphersuite::Sha256, "BLS12-381-SHA-256", "8.4", "D.2");
}

/// BBS-12 8.3 and D.1. Full applicable SHAKE-256 vector cross-check.
#[test]
fn shake256_all_bbs_vectors() {
    suite(Ciphersuite::Shake256, "BLS12-381-SHAKE-256", "8.3", "D.1");
}
