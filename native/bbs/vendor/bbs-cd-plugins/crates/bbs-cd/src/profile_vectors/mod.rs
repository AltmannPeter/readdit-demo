//! IMPLEMENTERS.md 5–11: independent Rust fixture runner, confined to the test build.
//! Direct subroutine fixtures do not expose a reusable proof-state API to callers.
mod codec;
mod dispatch;
mod trace;

use crate::{BbsError, params::Ciphersuite};
use codec::{RunError, hex};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

const OPERATIONS: [(&str, usize); 17] = [
    ("CoreProofGen", 6),
    ("CoreProofVerify", 6),
    ("CoreSign", 5),
    ("CoreVerify", 2),
    ("CreateGenerators", 2),
    ("HashToScalar", 3),
    ("KeyGen", 1),
    ("MessagesToScalars", 5),
    ("OctetsToProof", 17),
    ("PrecomputeCommitment", 12),
    ("PresentationContext", 7),
    ("ProofFinalize", 2),
    ("ProofGen", 27),
    ("ProofInit", 3),
    ("ProofVerify", 35),
    ("Sign", 10),
    ("Verify", 25),
];
const TRACE_ORDER: [&str; 18] = [
    "messageScalars",
    "domain",
    "commitments",
    "A_bar",
    "B_bar",
    "D",
    "T1",
    "T2",
    "C_tildes",
    "challenge",
    "apiId",
    "disclosedIndexes",
    "undisclosedIndexes",
    "commitmentIndexes",
    "committedScalars",
    "commitmentRands",
    "randomScalars",
    "sTildes",
];

/// IMPLEMENTERS.md 5. Read fixture metadata strictly; a harness error cannot count as INVALID.
fn read_json(path: &Path) -> Result<Value, String> {
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// IMPLEMENTERS.md 3. Enumerate all JSON cases, independent of the expected manifest.
fn collect_json(path: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            collect_json(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(path);
        }
    }
    Ok(())
}

/// IMPLEMENTERS.md 11. Normalize only the informative reason, never an output or outcome.
fn expected_outcome(expected: &Value) -> Result<Value, String> {
    let object = expected.as_object().ok_or("expected must be an object")?;
    if object.get("abort") == Some(&Value::Bool(true)) && object.len() == 1 {
        return Ok(json!({"abort":true}));
    }
    if let Some(result) = object.get("result") {
        if object.len() != 1 {
            return Err("ambiguous expected result".into());
        }
        let valid = result
            .get("valid")
            .and_then(Value::as_bool)
            .ok_or("expected result.valid missing")?;
        return Ok(json!({"result":{"valid":valid}}));
    }
    if object.contains_key("output")
        && object
            .keys()
            .all(|key| key == "output" || key == "addZkpInfo")
    {
        return Ok(expected.clone());
    }
    Err("unrecognized expected outcome".into())
}

/// IMPLEMENTERS.md 11. Compare supplied trace fields in the specified diagnostic order.
fn first_trace_difference(expected: &Value, actual: &Value) -> Option<String> {
    for key in TRACE_ORDER {
        if let Some(wanted) = expected.get(key) {
            match actual.get(key) {
                Some(got) if got == wanted => (),
                Some(got) => return Some(format!("{key}: expected {wanted}; actual {got}")),
                None => return Some(format!("{key}: expected {wanted}; actual unavailable")),
            }
        }
    }
    if let Some(fields) = expected.as_object() {
        for key in fields.keys() {
            if !TRACE_ORDER.contains(&key.as_str()) {
                return Some(format!("unsupported supplied trace field {key}"));
            }
        }
    }
    None
}

/// IMPLEMENTERS.md 3 and 11. Check every frozen case and print deterministic per-case totals.
#[test]
fn all_profile_fixtures() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = read_json(&root.join("tests/data/profile_manifest.json")).unwrap();
    let entries = manifest.as_array().expect("manifest array");
    assert_eq!(entries.len(), 336, "the supplied set contains 336 cases");
    let mut paths = Vec::new();
    collect_json(&root.join("fixtures/profile"), &mut paths).unwrap();
    paths.sort();
    let manifest_paths: Vec<_> = entries
        .iter()
        .map(|e| root.join(e["path"].as_str().unwrap()))
        .collect();
    assert_eq!(
        paths, manifest_paths,
        "missing, extra, or reordered manifest paths"
    );
    let mut counts: BTreeMap<(String, String), (usize, usize)> = BTreeMap::new();
    let mut failures = Vec::new();
    let mut results = Vec::new();
    let mut input_rejections = Vec::new();
    let mut trace_fields_checked = 0usize;
    for (path, entry) in paths.iter().zip(entries) {
        let relative = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .to_string();
        let bytes = fs::read(path).unwrap();
        assert_eq!(
            hex(&Sha256::digest(&bytes)),
            entry["sha256"].as_str().unwrap(),
            "frozen fixture changed: {relative}"
        );
        let case: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(case["specVersion"], "v0.5", "{relative}");
        assert_eq!(case["baseline"], "BBS-12", "{relative}");
        let suite_name = case["ciphersuite"].as_str().expect("ciphersuite string");
        let suite = match suite_name {
            "BLS12-381-SHA-256" => Ciphersuite::Sha256,
            "BLS12-381-SHAKE-256" => Ciphersuite::Shake256,
            _ => panic!("unknown suite in {relative}"),
        };
        let operation = case["operation"].as_str().expect("operation string");
        assert_eq!(
            path.parent().unwrap().file_name().unwrap(),
            operation,
            "operation directory mismatch"
        );
        assert_eq!(
            path.parent()
                .unwrap()
                .parent()
                .unwrap()
                .file_name()
                .unwrap(),
            suite_name,
            "suite directory mismatch"
        );
        let expected = expected_outcome(&case["expected"]).unwrap();
        let result = dispatch::execute(suite, operation, &case["input"], case.get("mockedRng"));
        let mut first_divergence = None;
        let mut input_rejection = None;
        let (actual, problem) = match result {
            Ok(execution) => {
                input_rejection = execution.input_rejection;
                let actual = match execution.outcome {
                    Ok(value) => value,
                    Err(BbsError::Invalid) => json!({"result":{"valid":false}}),
                    Err(BbsError::Abort(_)) => json!({"abort":true}),
                };
                let mismatch = actual != expected;
                // Positive traces are conformance assertions. On negative-output mismatches,
                // supplied traces are diagnostic, since invalid inputs can stop calculation.
                let successful = expected.get("output").is_some()
                    || expected.pointer("/result/valid") == Some(&Value::Bool(true));
                if (mismatch || successful)
                    && case
                        .get("trace")
                        .is_some_and(|t| t.as_object().is_some_and(|m| !m.is_empty()))
                {
                    let actual_trace =
                        trace::recompute(suite, operation, &case["input"], &execution.draws);
                    first_divergence = first_trace_difference(&case["trace"], &actual_trace);
                    if successful {
                        trace_fields_checked += case["trace"].as_object().unwrap().len();
                    }
                }
                let problem = if mismatch {
                    Some(format!("expected {expected}; actual {actual}"))
                } else if successful {
                    first_divergence
                        .as_ref()
                        .map(|s| format!("trace mismatch: {s}"))
                } else {
                    None
                };
                (actual, problem)
            }
            Err(error) => {
                let description = match error {
                    RunError::Harness(s) => s,
                    RunError::Operation(e) => format!("unhandled operation error: {e}"),
                    RunError::InputInvalid(s) => format!("unhandled input boundary rejection: {s}"),
                };
                (Value::Null, Some(format!("harness error: {description}")))
            }
        };
        let passed = problem.is_none();
        let count = counts
            .entry((suite_name.into(), operation.into()))
            .or_default();
        if passed {
            count.0 += 1;
            println!("PASS {relative}");
        } else {
            count.1 += 1;
            let message = format!(
                "FAIL {relative}: {}; first trace divergence: {}",
                problem.as_ref().unwrap(),
                first_divergence.as_deref().unwrap_or("none available")
            );
            println!("{message}");
            failures.push(message);
        }
        if let Some(reason) = &input_rejection {
            input_rejections.push(json!({"path":relative,"reason":reason,"passed":passed}));
        }
        let mut case_result = json!({"path":relative,"passed":passed,
            "firstDivergence":first_divergence,"inputRejection":input_rejection,"problem":problem});
        if !passed {
            case_result["expected"] = expected;
            case_result["actual"] = actual;
        }
        results.push(case_result);
    }
    let mut totals = Vec::new();
    for suite in ["BLS12-381-SHA-256", "BLS12-381-SHAKE-256"] {
        for (operation, wanted) in OPERATIONS {
            let (passed, failed) = counts
                .get(&(suite.into(), operation.into()))
                .copied()
                .unwrap_or_default();
            assert_eq!(
                passed + failed,
                wanted,
                "missing operation cases {suite}/{operation}"
            );
            println!("TOTAL {suite} {operation}: {passed} pass, {failed} fail");
            totals.push(
                json!({"ciphersuite":suite,"operation":operation,"passed":passed,"failed":failed}),
            );
        }
    }
    assert_eq!(counts.len(), 34, "unexpected suite or operation");
    println!(
        "PROFILE TOTAL: {} pass, {} fail; {trace_fields_checked} positive trace fields checked; {} decoded-input rejections inventoried",
        336 - failures.len(),
        failures.len(),
        input_rejections.len()
    );
    for rejection in &input_rejections {
        println!("INPUT_REJECTION {rejection}");
    }
    if let Ok(output) = std::env::var("BBS_PROFILE_REPORT") {
        let report = json!({"specVersion":"v0.5","baseline":"BBS-12","passed":336-failures.len(),
            "failed":failures.len(),"positiveTraceFieldsChecked":trace_fields_checked,
            "inputRejections":input_rejections,"totals":totals,"cases":results});
        fs::write(
            output,
            serde_json::to_string_pretty(&report).unwrap() + "\n",
        )
        .expect("write requested report");
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// IMPLEMENTERS.md 5. Verification failure and ABORT are never interchangeable.
#[test]
fn outcome_and_diagnostic_contracts() {
    assert_eq!(
        expected_outcome(&json!({"result":{"valid":false,"reason":"x"}})).unwrap(),
        json!({"result":{"valid":false}})
    );
    assert_ne!(
        expected_outcome(&json!({"abort":true})).unwrap(),
        json!({"result":{"valid":false}})
    );
    assert!(expected_outcome(&json!({"output":"00","abort":true})).is_err());
    let expected = json!({"domain":"a","messageScalars":["b"]});
    let actual = json!({"domain":"c","messageScalars":["d"]});
    assert!(
        first_trace_difference(&expected, &actual)
            .unwrap()
            .starts_with("messageScalars:")
    );
    assert!(
        first_trace_difference(&expected, &json!({}))
            .unwrap()
            .contains("unavailable")
    );
    assert!(
        first_trace_difference(&json!({"newField":1}), &json!({}))
            .unwrap()
            .contains("unsupported")
    );
}
