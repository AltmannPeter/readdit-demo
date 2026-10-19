//! Execute each profile fixture through the implementation's own operations.
use serde_json::{Value, json};

use super::codec::*;
use crate::core::{CoreProofGen, CoreProofVerify, CoreSign, CoreVerify, ProofInit};
use crate::interface::{KeyGen, PrecomputeCommitment, ProofGen, ProofVerify, Sign, SkToPk, Verify};
use crate::mock_rng::{ProfileRng, ScalarOverride};
use crate::params::Ciphersuite;
use crate::proof_protocol::ProofFinalize;
use crate::types::{ProofOutput, ScalarInput};
use crate::utils::{
    create_generators, hash_to_scalar, messages_to_scalars, octets_to_proof, octets_to_signature,
    presentation_context, proof_to_octets,
};
use crate::{BbsResult, INVALID};

pub(super) struct Execution {
    pub outcome: BbsResult<Value>,
    pub input_rejection: Option<String>,
    pub draws: Vec<Vec<ScalarInput>>,
}

/// Fixture randomness contract: no operation in this harness uses OS randomness.
pub(super) fn make_rng(suite: Ciphersuite, mocked: Option<&Value>) -> RunResult<ProfileRng> {
    let mocked = mocked
        .ok_or_else(|| RunError::Harness("randomized operation requires mockedRng".into()))?;
    let seed = bytes(mocked, "seed")?;
    let dst = bytes(mocked, "dst")?;
    let mut overrides = Vec::new();
    if mocked.get("overrides").is_some() {
        for entry in array(mocked, "overrides")? {
            let call = count(entry, "call")?;
            if call == 0 {
                return Err(RunError::Harness("override call must start at 1".into()));
            }
            let index = usize::try_from(count(entry, "index")?)
                .map_err(|_| RunError::Harness("override index exceeds usize".into()))?;
            overrides.push(ScalarOverride {
                call,
                index,
                value: scalar(string(entry, "value")?)?,
            });
        }
    }
    Ok(ProfileRng::new(suite, seed, dst, overrides))
}

/// Spec 3.6.3: NONE and an explicitly empty vector have different call schedules.
fn precomputed(input: &Value) -> RunResult<Option<Vec<ScalarInput>>> {
    if field(input, "precomputedRands")?.is_null() {
        Ok(None)
    } else {
        Ok(Some(scalars(input, "precomputedRands")?))
    }
}
/// Spec 3.5.3: expose private opening information only as fixture output.
fn proof_output(output: ProofOutput) -> Value {
    let (proof, (committed_messages, commitment_rands)) = output;
    json!({"output":hex(&proof),"addZkpInfo":{"committedMessages":scalar_values(&committed_messages),"commitmentRands":scalar_values(&commitment_rands)}})
}

/// Fixture schema: validate all fields before an early operation INVALID can hide one.
fn validate_schema(operation: &str, input: &Value) -> RunResult<()> {
    let required: &[&str] = match operation {
        "KeyGen" => &["keyMaterial", "keyInfo"],
        "Sign" => &["SK", "PK", "header", "messages", "messageTypes"],
        "Verify" => &["PK", "signature", "header", "messages", "messageTypes"],
        "ProofGen" => &[
            "PK",
            "signature",
            "header",
            "presentationHeader",
            "messages",
            "messageTypes",
            "messageDisclosures",
            "precomputedRands",
        ],
        "ProofVerify" => &[
            "PK",
            "proof",
            "header",
            "presentationHeader",
            "disclosedMessages",
            "commitments",
            "messageTypes",
            "messageDisclosures",
        ],
        "PrecomputeCommitment" => &["committedMessages", "commitmentIndexes", "messageTypes"],
        "CoreSign" => &[
            "SK",
            "PK",
            "generators",
            "header",
            "messageScalars",
            "apiId",
        ],
        "CoreVerify" => &[
            "PK",
            "signature",
            "generators",
            "header",
            "messageScalars",
            "apiId",
        ],
        "CoreProofGen" => &[
            "PK",
            "signature",
            "generators",
            "header",
            "presentationHeader",
            "messageScalars",
            "disclosedIndexes",
            "commitmentIndexes",
            "precomputedRands",
            "apiId",
        ],
        "CoreProofVerify" => &[
            "PK",
            "proof",
            "generators",
            "header",
            "presentationHeader",
            "disclosedScalars",
            "disclosedIndexes",
            "commitmentIndexes",
            "commitments",
            "apiId",
        ],
        "ProofInit" => &[
            "PK",
            "signature",
            "generators",
            "randomScalars",
            "header",
            "messageScalars",
            "undisclosedIndexes",
            "commitmentIndexes",
            "sTildes",
            "apiId",
        ],
        "ProofFinalize" => &[
            "initRes",
            "challenge",
            "eValue",
            "randomScalars",
            "undisclosedMessages",
            "commitments",
            "commitmentRands",
            "sTildes",
        ],
        "MessagesToScalars" => &["messages", "messageTypes", "apiId"],
        "PresentationContext" => &["presentationHeader", "commitments"],
        "HashToScalar" => &["msg", "dst"],
        "CreateGenerators" => &["count", "apiId"],
        "OctetsToProof" => &["proof"],
        _ => {
            return Err(RunError::Harness(format!(
                "unsupported operation {operation}"
            )));
        }
    };
    for &name in required {
        match name {
            "SK" | "challenge" | "eValue" => {
                scalar(string(input, name)?)?;
            }
            "messages" | "disclosedMessages" | "committedMessages" => {
                messages(input, name)?;
            }
            "messageTypes" => {
                message_types(input, name)?;
            }
            "messageDisclosures" => {
                disclosures(input, name)?;
            }
            "disclosedIndexes" | "undisclosedIndexes" | "commitmentIndexes" => {
                indexes(input, name)?;
            }
            "messageScalars"
            | "disclosedScalars"
            | "randomScalars"
            | "sTildes"
            | "undisclosedMessages"
            | "commitmentRands" => {
                scalars(input, name)?;
            }
            "precomputedRands" => {
                precomputed(input)?;
            }
            "count" => {
                count(input, name)?;
            }
            "generators" | "commitments" => {
                validate_point_octets(input, name)?;
            }
            "initRes" => {
                let init = field(input, name)?;
                for point in ["A_bar", "B_bar", "D", "T1", "T2"] {
                    bytes(init, point)?;
                }
                scalar(string(init, "domain")?)?;
                validate_point_octets(init, "C_tildes")?;
            }
            _ => {
                bytes(input, name)?;
            }
        }
    }
    if operation == "KeyGen" && input.get("keyDst").is_some() {
        bytes(input, "keyDst")?;
    }
    Ok(())
}

/// Fixture schema: check point hex now; cryptographic decoding remains in dispatch.
fn validate_point_octets(input: &Value, name: &str) -> RunResult<()> {
    for value in array(input, name)? {
        unhex(
            value
                .as_str()
                .ok_or_else(|| RunError::Harness(format!("{name}: expected point hex string")))?,
        )?;
    }
    Ok(())
}
/// Fixture contract: normalize library outcomes without hiding harness failures.
pub(super) fn execute(
    suite: Ciphersuite,
    operation: &str,
    input: &Value,
    mocked: Option<&Value>,
) -> RunResult<Execution> {
    if !input.is_object() {
        return Err(RunError::Harness("input must be an object".into()));
    }
    validate_schema(operation, input)?;
    let mut rng = if matches!(
        operation,
        "ProofGen" | "CoreProofGen" | "PrecomputeCommitment"
    ) {
        Some(make_rng(suite, mocked)?)
    } else {
        None
    };
    let result = perform(suite, operation, input, rng.as_mut());
    let draws = rng.map(|r| r.calls).unwrap_or_default();
    match result {
        Ok(value) => Ok(Execution {
            outcome: Ok(value),
            input_rejection: None,
            draws,
        }),
        Err(RunError::Operation(error)) => Ok(Execution {
            outcome: Err(error),
            input_rejection: None,
            draws,
        }),
        Err(RunError::InputInvalid(reason)) => Ok(Execution {
            outcome: Err(INVALID),
            input_rejection: Some(reason),
            draws,
        }),
        Err(error @ RunError::Harness(_)) => Err(error),
    }
}

/// Fixture contract: call the spec functions; all cryptographic work stays there.
fn perform(
    suite: Ciphersuite,
    operation: &str,
    input: &Value,
    rng: Option<&mut ProfileRng>,
) -> RunResult<Value> {
    let required_rng = || RunError::Harness("randomized operation requires mockedRng".into());
    Ok(match operation {
        "KeyGen" => {
            let dst = input
                .get("keyDst")
                .map(|_| bytes(input, "keyDst"))
                .transpose()?;
            let sk = KeyGen(
                suite,
                &bytes(input, "keyMaterial")?,
                &bytes(input, "keyInfo")?,
                dst.as_deref(),
            )?;
            json!({"output":{"SK":hex(&sk.0),"PK":hex(&SkToPk(sk)?)}})
        }
        "Sign" => {
            json!({"output":hex(&Sign(suite,scalar(string(input,"SK")?)?,&bytes(input,"PK")?,&bytes(input,"header")?,&messages(input,"messages")?,&message_types(input,"messageTypes")?)?)})
        }
        "Verify" => {
            Verify(
                suite,
                &bytes(input, "PK")?,
                &bytes(input, "signature")?,
                &bytes(input, "header")?,
                &messages(input, "messages")?,
                &message_types(input, "messageTypes")?,
            )?;
            json!({"result":{"valid":true}})
        }
        "ProofGen" => {
            let precomputed = precomputed(input)?;
            proof_output(ProofGen(
                suite,
                &bytes(input, "PK")?,
                &bytes(input, "signature")?,
                &bytes(input, "header")?,
                &bytes(input, "presentationHeader")?,
                &messages(input, "messages")?,
                &message_types(input, "messageTypes")?,
                &disclosures(input, "messageDisclosures")?,
                precomputed.as_deref(),
                Some(rng.ok_or_else(required_rng)?),
            )?)
        }
        "ProofVerify" => {
            ProofVerify(
                suite,
                &bytes(input, "PK")?,
                &bytes(input, "proof")?,
                &bytes(input, "header")?,
                &bytes(input, "presentationHeader")?,
                &messages(input, "disclosedMessages")?,
                &points(input, "commitments", false)?,
                &message_types(input, "messageTypes")?,
                &disclosures(input, "messageDisclosures")?,
            )?;
            json!({"result":{"valid":true}})
        }
        "PrecomputeCommitment" => {
            let (commitments, rands) = PrecomputeCommitment(
                suite,
                &messages(input, "committedMessages")?,
                &indexes(input, "commitmentIndexes")?,
                &message_types(input, "messageTypes")?,
                Some(rng.ok_or_else(required_rng)?),
            )?;
            json!({"output":{"commitments":point_values(&commitments),"commitmentRands":scalar_values(&rands)}})
        }
        "CoreSign" => {
            json!({"output":hex(&CoreSign(suite,scalar(string(input,"SK")?)?,&bytes(input,"PK")?,&points(input,"generators",true)?,&bytes(input,"header")?,&scalars(input,"messageScalars")?,&bytes(input,"apiId")?)?)})
        }
        "CoreVerify" => {
            CoreVerify(
                suite,
                &bytes(input, "PK")?,
                &bytes(input, "signature")?,
                &points(input, "generators", true)?,
                &bytes(input, "header")?,
                &scalars(input, "messageScalars")?,
                &bytes(input, "apiId")?,
            )?;
            json!({"result":{"valid":true}})
        }
        "CoreProofGen" => {
            let precomputed = precomputed(input)?;
            proof_output(CoreProofGen(
                suite,
                &bytes(input, "PK")?,
                &bytes(input, "signature")?,
                &points(input, "generators", true)?,
                &bytes(input, "header")?,
                &bytes(input, "presentationHeader")?,
                &scalars(input, "messageScalars")?,
                &indexes(input, "disclosedIndexes")?,
                &indexes(input, "commitmentIndexes")?,
                precomputed.as_deref(),
                &bytes(input, "apiId")?,
                rng.ok_or_else(required_rng)?,
            )?)
        }
        "CoreProofVerify" => {
            CoreProofVerify(
                suite,
                &bytes(input, "PK")?,
                &bytes(input, "proof")?,
                &points(input, "generators", true)?,
                &bytes(input, "header")?,
                &bytes(input, "presentationHeader")?,
                &scalars(input, "disclosedScalars")?,
                &indexes(input, "disclosedIndexes")?,
                &indexes(input, "commitmentIndexes")?,
                &points(input, "commitments", false)?,
                &bytes(input, "apiId")?,
            )?;
            json!({"result":{"valid":true}})
        }
        "ProofInit" => {
            let signature = octets_to_signature(&bytes(input, "signature")?)?;
            let init = ProofInit(
                suite,
                &bytes(input, "PK")?,
                &signature,
                &points(input, "generators", true)?,
                &scalars(input, "randomScalars")?,
                &bytes(input, "header")?,
                &scalars(input, "messageScalars")?,
                &indexes(input, "undisclosedIndexes")?,
                &indexes(input, "commitmentIndexes")?,
                &scalars(input, "sTildes")?,
                &bytes(input, "apiId")?,
            )?;
            json!({"output":init_value(&init)})
        }
        "ProofFinalize" => {
            json!({"output":hex(&ProofFinalize(suite,&init_result(field(input,"initRes")?)?,scalar(string(input,"challenge")?)?,scalar(string(input,"eValue")?)?,&scalars(input,"randomScalars")?,&scalars(input,"undisclosedMessages")?,&points(input,"commitments",true)?,&scalars(input,"commitmentRands")?,&scalars(input,"sTildes")?)?)})
        }
        "MessagesToScalars" => {
            json!({"output":scalar_values(&messages_to_scalars(suite,&messages(input,"messages")?,&message_types(input,"messageTypes")?,&bytes(input,"apiId")?)?)})
        }
        "PresentationContext" => {
            json!({"output":hex(&presentation_context(&bytes(input,"presentationHeader")?,&points(input,"commitments",true)?)?)})
        }
        "HashToScalar" => {
            json!({"output":hex(&hash_to_scalar(suite,&bytes(input,"msg")?,&bytes(input,"dst")?)?.0)})
        }
        "CreateGenerators" => {
            json!({"output":point_values(&create_generators(suite,count(input,"count")? as u128,&bytes(input,"apiId")?)?)})
        }
        "OctetsToProof" => {
            json!({"output":hex(&proof_to_octets(&octets_to_proof(&bytes(input,"proof")?)?)?)})
        }
        _ => {
            return Err(RunError::Harness(format!(
                "unsupported operation {operation}"
            )));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Harness errors must remain errors even if a fixture expects INVALID.
    #[test]
    fn malformed_input_and_missing_rng_do_not_become_invalid() {
        for operation in [
            "Sign",
            "MessagesToScalars",
            "KeyGen",
            "ProofGen",
            "CoreProofGen",
            "PrecomputeCommitment",
        ] {
            assert!(matches!(
                execute(Ciphersuite::Sha256, operation, &json!({}), None),
                Err(RunError::Harness(_))
            ));
        }
        assert!(matches!(
            execute(
                Ciphersuite::Sha256,
                "HashToScalar",
                &json!({"msg":"gg","dst":""}),
                None
            ),
            Err(RunError::Harness(_))
        ));
        assert!(matches!(
            execute(Ciphersuite::Sha256, "unknown", &json!({}), None),
            Err(RunError::Harness(_))
        ));
        // An undecodable signature must not hide missing or malformed later fields.
        let malformed = json!({"PK":"", "signature":"", "generators":[],
            "randomScalars":[], "header":"", "messageScalars":[],
            "undisclosedIndexes":[], "commitmentIndexes":[], "sTildes":[], "apiId":"gg"});
        assert!(matches!(
            execute(Ciphersuite::Sha256, "ProofInit", &malformed, None),
            Err(RunError::Harness(_))
        ));
        // Caller point rejection also cannot hide malformed hex in another field.
        let malformed = json!({"SK":"00".repeat(32),"PK":"", "generators":["00"],
            "header":"gg", "messageScalars":[], "apiId":""});
        assert!(matches!(
            execute(Ciphersuite::Sha256, "CoreSign", &malformed, None),
            Err(RunError::Harness(_))
        ));
    }
}
