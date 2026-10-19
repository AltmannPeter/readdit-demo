//! Spec 3.5–3.7 and 4.1–4.2: independently recomputed fixture diagnostics.
//!
//! Only invocation inputs and scalar draws captured during that invocation enter
//! this module. Fixture expectations and stored traces never supply intermediates.

use bls12_381::G1Projective;
use serde_json::{Map, Value, json};

use super::codec::{
    RunResult, bytes, disclosures, hex, indexes, init_result, init_value, message_types, messages,
    point_values, points, scalar_values, scalars,
};
use crate::INVALID;
use crate::core::ProofInit;
use crate::helpers::{
    complement, disclosure_indexes, select, valid_generators, valid_message_types,
    valid_message_vector,
};
use crate::params::Ciphersuite;
use crate::proof_protocol::{ProofChallengeCalculate, ProofVerifyInit};
use crate::types::{Index, InitResult, ScalarInput};
use crate::utils::{
    calculate_domain, compute_commitments, create_generators, messages_to_scalars, octets_to_proof,
    octets_to_signature,
};

/// Spec 1.4.1: retain integer indexes as integers in diagnostic metadata.
fn index_values(indexes: &[Index]) -> Value {
    Value::Array(
        indexes
            .iter()
            .map(|index| match index {
                Index::Integer(value) => json!(value),
                Index::Other(value) => json!(value),
            })
            .collect(),
    )
}

/// Spec 3.7.1/3.7.3: copy actual initialization results into diagnostics.
fn add_init(trace: &mut Map<String, Value>, init: &InitResult) {
    if let Value::Object(fields) = init_value(init) {
        trace.extend(fields);
    }
}

/// Spec 4.2.3: validate the generator partition before calculating its domain.
fn add_domain(
    trace: &mut Map<String, Value>,
    suite: Ciphersuite,
    input: &Value,
    generators: &[G1Projective],
    message_count: usize,
    api_id: &[u8],
) -> RunResult<()> {
    if !valid_generators(suite, generators, message_count as u128) {
        return Err(INVALID.into());
    }
    let domain = calculate_domain(
        suite,
        &bytes(input, "PK")?,
        &generators[0],
        &generators[1..],
        &bytes(input, "header")?,
        api_id,
    )?;
    trace.insert("domain".into(), json!(hex(&domain.0)));
    Ok(())
}

/// Spec 3.6.3: replay the initialization with the invocation's actual mask calls.
#[allow(clippy::too_many_arguments)]
fn proof_generation(
    trace: &mut Map<String, Value>,
    suite: Ciphersuite,
    input: &Value,
    draws: &[Vec<ScalarInput>],
    api_id: &[u8],
    message_scalars: &[ScalarInput],
    generators: &[G1Projective],
    disclosed_indexes: &[Index],
    commitment_indexes: &[Index],
) -> RunResult<()> {
    let undisclosed_indexes = complement(disclosed_indexes, message_scalars.len())?;
    let committed_scalars = select(message_scalars, commitment_indexes)?;
    trace.insert("disclosedIndexes".into(), index_values(disclosed_indexes));
    trace.insert(
        "undisclosedIndexes".into(),
        index_values(&undisclosed_indexes),
    );
    trace.insert("commitmentIndexes".into(), index_values(commitment_indexes));
    trace.insert("committedScalars".into(), scalar_values(&committed_scalars));
    add_domain(
        trace,
        suite,
        input,
        generators,
        message_scalars.len(),
        api_id,
    )?;

    let precomputed = input
        .get("precomputedRands")
        .filter(|value| !value.is_null());
    let (commitment_rands, random_call) = if precomputed.is_some() {
        (scalars(input, "precomputedRands")?, 0)
    } else {
        (draws.first().ok_or(INVALID)?.clone(), 1)
    };
    trace.insert("commitmentRands".into(), scalar_values(&commitment_rands));
    let commitments = compute_commitments(suite, &committed_scalars, &commitment_rands, api_id)?;
    trace.insert("commitments".into(), point_values(&commitments));
    let random_scalars = draws.get(random_call).ok_or(INVALID)?;
    trace.insert("randomScalars".into(), scalar_values(random_scalars));
    let s_tildes = draws.get(random_call + 1).ok_or(INVALID)?;
    trace.insert("sTildes".into(), scalar_values(s_tildes));

    let signature = octets_to_signature(&bytes(input, "signature")?)?;
    let init = ProofInit(
        suite,
        &bytes(input, "PK")?,
        &signature,
        generators,
        random_scalars,
        &bytes(input, "header")?,
        message_scalars,
        &undisclosed_indexes,
        commitment_indexes,
        s_tildes,
        api_id,
    )?;
    add_init(trace, &init);
    let challenge = ProofChallengeCalculate(
        suite,
        &init,
        &select(message_scalars, disclosed_indexes)?,
        disclosed_indexes,
        &commitments,
        commitment_indexes,
        &bytes(input, "presentationHeader")?,
        api_id,
    )?;
    trace.insert("challenge".into(), json!(hex(&challenge.0)));
    Ok(())
}

/// Spec 3.6.4: reconstruct the transcript and hash it rather than echoing proof.c.
#[allow(clippy::too_many_arguments)]
fn proof_verification(
    trace: &mut Map<String, Value>,
    suite: Ciphersuite,
    input: &Value,
    api_id: &[u8],
    generators: &[G1Projective],
    disclosed_scalars: &[ScalarInput],
    disclosed_indexes: &[Index],
    commitment_indexes: &[Index],
) -> RunResult<()> {
    let proof = octets_to_proof(&bytes(input, "proof")?)?;
    let commitments = points(input, "commitments", false)?;
    if proof.commitments != commitments {
        return Err(INVALID.into());
    }
    let init = ProofVerifyInit(
        suite,
        &bytes(input, "PK")?,
        &proof,
        generators,
        &bytes(input, "header")?,
        disclosed_scalars,
        disclosed_indexes,
        commitment_indexes,
        api_id,
    )?;
    add_init(trace, &init);
    trace.insert("commitments".into(), point_values(&commitments));
    let challenge = ProofChallengeCalculate(
        suite,
        &init,
        disclosed_scalars,
        disclosed_indexes,
        &commitments,
        commitment_indexes,
        &bytes(input, "presentationHeader")?,
        api_id,
    )?;
    trace.insert("challenge".into(), json!(hex(&challenge.0)));
    Ok(())
}

/// Spec 3.5–3.7 and 4.1–4.2: return available independently computed trace fields.
///
/// A failed decoding or operation leaves earlier intermediates available and
/// stops calculations that depend on the failed result. No failed result is
/// converted into an invented scalar, point, or transcript.
pub(super) fn recompute(
    suite: Ciphersuite,
    operation: &str,
    input: &Value,
    draws: &[Vec<ScalarInput>],
) -> Value {
    let mut trace = Map::new();
    let _ = (|| -> RunResult<()> {
        match operation {
            "Sign" | "Verify" | "ProofGen" => {
                let api_id = suite.api_id();
                trace.insert("apiId".into(), json!(hex(&api_id)));
                let message_scalars = messages_to_scalars(
                    suite,
                    &messages(input, "messages")?,
                    &message_types(input, "messageTypes")?,
                    &api_id,
                )?;
                trace.insert("messageScalars".into(), scalar_values(&message_scalars));
                let generators =
                    create_generators(suite, message_scalars.len() as u128 + 1, &api_id)?;
                if operation == "ProofGen" {
                    let (disclosed, committed) = disclosure_indexes(
                        &disclosures(input, "messageDisclosures")?,
                        message_scalars.len() as u128,
                    )?;
                    proof_generation(
                        &mut trace,
                        suite,
                        input,
                        draws,
                        &api_id,
                        &message_scalars,
                        &generators,
                        &disclosed,
                        &committed,
                    )?;
                } else {
                    add_domain(
                        &mut trace,
                        suite,
                        input,
                        &generators,
                        message_scalars.len(),
                        &api_id,
                    )?;
                }
            }
            "ProofVerify" => {
                let api_id = suite.api_id();
                trace.insert("apiId".into(), json!(hex(&api_id)));
                let schema = message_types(input, "messageTypes")?;
                let states = disclosures(input, "messageDisclosures")?;
                if schema.len() != states.len() || !valid_message_types(&schema) {
                    return Err(INVALID.into());
                }
                let (disclosed, committed) = disclosure_indexes(&states, states.len() as u128)?;
                let disclosed_scalars = messages_to_scalars(
                    suite,
                    &messages(input, "disclosedMessages")?,
                    &select(&schema, &disclosed)?,
                    &api_id,
                )?;
                let generators = create_generators(suite, states.len() as u128 + 1, &api_id)?;
                proof_verification(
                    &mut trace,
                    suite,
                    input,
                    &api_id,
                    &generators,
                    &disclosed_scalars,
                    &disclosed,
                    &committed,
                )?;
            }
            "CoreSign" | "CoreVerify" | "CoreProofGen" => {
                let api_id = bytes(input, "apiId")?;
                trace.insert("apiId".into(), json!(hex(&api_id)));
                let message_scalars = scalars(input, "messageScalars")?;
                if !valid_message_vector(&message_scalars) {
                    return Err(INVALID.into());
                }
                trace.insert("messageScalars".into(), scalar_values(&message_scalars));
                let generators = points(input, "generators", true)?;
                if operation == "CoreProofGen" {
                    proof_generation(
                        &mut trace,
                        suite,
                        input,
                        draws,
                        &api_id,
                        &message_scalars,
                        &generators,
                        &indexes(input, "disclosedIndexes")?,
                        &indexes(input, "commitmentIndexes")?,
                    )?;
                } else {
                    add_domain(
                        &mut trace,
                        suite,
                        input,
                        &generators,
                        message_scalars.len(),
                        &api_id,
                    )?;
                }
            }
            "CoreProofVerify" => {
                let api_id = bytes(input, "apiId")?;
                trace.insert("apiId".into(), json!(hex(&api_id)));
                proof_verification(
                    &mut trace,
                    suite,
                    input,
                    &api_id,
                    &points(input, "generators", true)?,
                    &scalars(input, "disclosedScalars")?,
                    &indexes(input, "disclosedIndexes")?,
                    &indexes(input, "commitmentIndexes")?,
                )?;
            }
            "ProofInit" => {
                let api_id = bytes(input, "apiId")?;
                let message_scalars = scalars(input, "messageScalars")?;
                trace.insert("apiId".into(), json!(hex(&api_id)));
                trace.insert("messageScalars".into(), scalar_values(&message_scalars));
                let init = ProofInit(
                    suite,
                    &bytes(input, "PK")?,
                    &octets_to_signature(&bytes(input, "signature")?)?,
                    &points(input, "generators", true)?,
                    &scalars(input, "randomScalars")?,
                    &bytes(input, "header")?,
                    &message_scalars,
                    &indexes(input, "undisclosedIndexes")?,
                    &indexes(input, "commitmentIndexes")?,
                    &scalars(input, "sTildes")?,
                    &api_id,
                )?;
                add_init(&mut trace, &init);
            }
            "ProofFinalize" => {
                let init = init_result(input.get("initRes").ok_or(INVALID)?)?;
                add_init(&mut trace, &init);
            }
            "MessagesToScalars" => {
                let api_id = bytes(input, "apiId")?;
                let mapped = messages_to_scalars(
                    suite,
                    &messages(input, "messages")?,
                    &message_types(input, "messageTypes")?,
                    &api_id,
                )?;
                trace.insert("apiId".into(), json!(hex(&api_id)));
                trace.insert("messageScalars".into(), scalar_values(&mapped));
            }
            "PrecomputeCommitment" => {
                let api_id = suite.api_id();
                trace.insert("apiId".into(), json!(hex(&api_id)));
                let committed = indexes(input, "commitmentIndexes")?;
                let types = message_types(input, "messageTypes")?;
                if !valid_message_types(&types)
                    || !crate::helpers::valid_indexes(&committed, types.len() as u128)
                {
                    return Err(INVALID.into());
                }
                let mapped = messages_to_scalars(
                    suite,
                    &messages(input, "committedMessages")?,
                    &select(&types, &committed)?,
                    &api_id,
                )?;
                trace.insert("committedScalars".into(), scalar_values(&mapped));
                trace.insert("commitmentIndexes".into(), index_values(&committed));
                let rands = draws.first().ok_or(INVALID)?;
                trace.insert("commitmentRands".into(), scalar_values(rands));
                let commitments = compute_commitments(suite, &mapped, rands, &api_id)?;
                trace.insert("commitments".into(), point_values(&commitments));
            }
            _ => {}
        }
        Ok(())
    })();
    Value::Object(trace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BbsResult;
    use crate::interface::{ProofGen, Sign, SkToPk};
    use crate::types::{COMMIT, DISCLOSE, Message, SCALAR, ScalarSource};

    #[derive(Default)]
    struct RecordedDraws(Vec<Vec<ScalarInput>>);

    impl ScalarSource for RecordedDraws {
        /// Spec 4.2.1: capture every test invocation's actual scalar draws.
        fn calculate_random_scalars(&mut self, count: usize) -> BbsResult<Vec<ScalarInput>> {
            let values: Vec<_> = (0..count)
                .map(|i| ScalarInput::from(2 + 31 * self.0.len() as u64 + i as u64))
                .collect();
            self.0.push(values.clone());
            Ok(values)
        }
    }

    /// Spec 3.5.3: create inputs through the public operations, without fixtures.
    fn generated_case(suite: Ciphersuite) -> (Value, Vec<Vec<ScalarInput>>, Vec<u8>) {
        let PK = SkToPk(41u64.into()).unwrap();
        let mapped = [7u64.into(), 11u64.into()];
        let messages = mapped.map(Message::Scalar);
        let signature = Sign(
            suite,
            41u64.into(),
            &PK,
            b"header",
            &messages,
            &[SCALAR, SCALAR],
        )
        .unwrap();
        let mut rng = RecordedDraws::default();
        let (proof, _) = ProofGen(
            suite,
            &PK,
            &signature,
            b"header",
            b"presentation",
            &messages,
            &[SCALAR, SCALAR],
            &[DISCLOSE, COMMIT],
            None,
            Some(&mut rng),
        )
        .unwrap();
        (
            json!({
                "PK": hex(&PK), "signature": hex(&signature),
                "header": hex(b"header"), "presentationHeader": hex(b"presentation"),
                "messages": mapped.map(|value| json!({"scalar": hex(&value.0)})),
                "messageTypes": ["SCALAR", "SCALAR"],
                "messageDisclosures": ["DISCLOSE", "COMMIT"], "precomputedRands": null
            }),
            rng.0,
            proof,
        )
    }

    /// Spec 3.7.1–3.7.4: diagnostics depend on invocation inputs and captured masks.
    #[test]
    fn generation_trace_recomputes_inputs_and_captured_draws() {
        for suite in [Ciphersuite::Sha256, Ciphersuite::Shake256] {
            let (input, draws, proof_bytes) = generated_case(suite);
            let actual = recompute(suite, "ProofGen", &input, &draws);
            assert_eq!(actual.as_object().unwrap().len(), 18);
            let proof = octets_to_proof(&proof_bytes).unwrap();
            assert_eq!(actual["challenge"], json!(hex(&proof.challenge.0)));
            assert_eq!(actual["commitments"], point_values(&proof.commitments));
            assert_eq!(
                actual["A_bar"],
                json!(hex(&crate::primitives::point_to_octets_E1(&proof.A_bar)))
            );

            let mut changed = input.clone();
            changed["header"] = json!(hex(b"different header"));
            let changed_header = recompute(suite, "ProofGen", &changed, &draws);
            assert_ne!(actual["domain"], changed_header["domain"]);
            assert_ne!(actual["challenge"], changed_header["challenge"]);

            changed = input.clone();
            changed["presentationHeader"] = json!(hex(b"different presentation"));
            let changed_ph = recompute(suite, "ProofGen", &changed, &draws);
            assert_eq!(actual["domain"], changed_ph["domain"]);
            assert_ne!(actual["challenge"], changed_ph["challenge"]);

            changed = input.clone();
            changed["trace"] = json!({"domain": "invented", "challenge": "invented"});
            changed["expected"] = json!({"output": "invented"});
            assert_eq!(actual, recompute(suite, "ProofGen", &changed, &draws));

            let mut changed_draws = draws.clone();
            changed_draws[1][2] = 97u64.into();
            let changed_mask = recompute(suite, "ProofGen", &input, &changed_draws);
            assert_ne!(actual["T1"], changed_mask["T1"]);
            assert_ne!(actual["challenge"], changed_mask["challenge"]);
        }
    }

    /// Spec 3.7.3–3.7.4: verification hashes a reconstructed presentation transcript.
    #[test]
    fn verification_trace_hashes_reconstructed_transcript() {
        for suite in [Ciphersuite::Sha256, Ciphersuite::Shake256] {
            let (mut input, _, proof_bytes) = generated_case(suite);
            let proof = octets_to_proof(&proof_bytes).unwrap();
            input["proof"] = json!(hex(&proof_bytes));
            input["disclosedMessages"] = json!([{"scalar": hex(&ScalarInput::from(7).0)}]);
            input["commitments"] = point_values(&proof.commitments);
            let actual = recompute(suite, "ProofVerify", &input, &[]);
            assert_eq!(actual["challenge"], json!(hex(&proof.challenge.0)));
            input["presentationHeader"] = json!(hex(b"changed"));
            let changed = recompute(suite, "ProofVerify", &input, &[]);
            assert_ne!(actual["challenge"], changed["challenge"]);
            assert_eq!(actual["domain"], changed["domain"]);
        }
    }

    /// Spec 3.6.3: an unavailable draw preserves earlier diagnostics without panic.
    #[test]
    fn incomplete_invocations_preserve_only_available_intermediates() {
        let suite = Ciphersuite::Sha256;
        let (input, _, _) = generated_case(suite);
        let partial = recompute(suite, "ProofGen", &input, &[]);
        assert!(partial.get("domain").is_some());
        assert!(partial.get("randomScalars").is_none());
        assert!(partial.get("challenge").is_none());
        assert!(recompute(suite, "ProofGen", &json!({}), &[]).is_object());
    }
}
