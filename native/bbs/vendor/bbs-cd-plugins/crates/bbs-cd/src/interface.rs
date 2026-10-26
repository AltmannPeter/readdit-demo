//! Spec 3.4–3.5 and 4.1.3: key, signature, proof, and commitment interfaces.

use bls12_381::G1Projective;

use crate::core::{CoreProofGen, CoreSign, CoreVerify, core_proof_verify_decoded};
use crate::helpers::{
    disclosure_indexes, nonzero_scalar, select, valid_indexes, valid_message_types,
};
use crate::params::{BP2, Ciphersuite};
use crate::primitives::{I2OSP, point_to_octets_E2};
use crate::types::{
    CommitmentOutput, DisclosureState, Index, Message, MessageType, OsRandom, ProofOutput,
    ScalarInput, ScalarSource,
};
use crate::utils::{
    compute_commitments, create_generators, hash_to_scalar, messages_to_scalars, octets_to_proof,
};
use crate::{BbsResult, INVALID};

/// Spec 3.4.1 KeyGen. Derive a nonzero secret key under the selected key DST.
pub fn KeyGen(
    suite: Ciphersuite,
    key_material: &[u8],
    key_info: &[u8],
    key_dst: Option<&[u8]>,
) -> BbsResult<ScalarInput> {
    if key_material.len() < 32 || key_info.len() > 65535 {
        return Err(INVALID);
    }
    let derive_input = [key_material, &I2OSP(key_info.len() as u128, 2)?, key_info].concat();
    let default_dst = [suite.ciphersuite_id(), b"KEYGEN_DST_"].concat();
    let SK = hash_to_scalar(suite, &derive_input, key_dst.unwrap_or(&default_dst))?;
    if !nonzero_scalar(SK) {
        return Err(INVALID);
    }
    Ok(SK)
}

/// Spec 3.4.2 SkToPk. Validate before multiplying the public-key base point.
pub fn SkToPk(SK: ScalarInput) -> BbsResult<Vec<u8>> {
    if !nonzero_scalar(SK) {
        return Err(INVALID);
    }
    let W = BP2() * SK.to_scalar()?;
    Ok(point_to_octets_E2(&W).to_vec())
}

/// Spec 3.5.1 Sign. Map the full typed message vector before signing.
pub fn Sign(
    suite: Ciphersuite,
    SK: ScalarInput,
    PK: &[u8],
    header: &[u8],
    messages: &[Message],
    message_types: &[MessageType],
) -> BbsResult<Vec<u8>> {
    let api_id = suite.api_id();
    let message_scalars = messages_to_scalars(suite, messages, message_types, &api_id)?;
    let L = message_scalars.len();
    let generators = create_generators(suite, L as u128 + 1, &api_id)?;
    CoreSign(
        suite,
        SK,
        PK,
        &generators,
        header,
        &message_scalars,
        &api_id,
    )
}

/// Spec 3.5.2 Verify. Ok(()) denotes VALID; INVALID and ABORT propagate.
pub fn Verify(
    suite: Ciphersuite,
    PK: &[u8],
    signature: &[u8],
    header: &[u8],
    messages: &[Message],
    message_types: &[MessageType],
) -> BbsResult<()> {
    let api_id = suite.api_id();
    let message_scalars = messages_to_scalars(suite, messages, message_types, &api_id)?;
    let L = message_scalars.len();
    let generators = create_generators(suite, L as u128 + 1, &api_id)?;
    CoreVerify(
        suite,
        PK,
        signature,
        &generators,
        header,
        &message_scalars,
        &api_id,
    )
}

/// Spec 3.5.3 ProofGen. Optional RNG supplies one advancing scalar stream.
#[allow(clippy::too_many_arguments)]
pub fn ProofGen(
    suite: Ciphersuite,
    PK: &[u8],
    signature: &[u8],
    header: &[u8],
    ph: &[u8],
    messages: &[Message],
    message_types: &[MessageType],
    message_disclosures: &[DisclosureState],
    precomputed_rands: Option<&[ScalarInput]>,
    rng: Option<&mut dyn ScalarSource>,
) -> BbsResult<ProofOutput> {
    let api_id = suite.api_id();
    let message_scalars = messages_to_scalars(suite, messages, message_types, &api_id)?;
    let L = message_scalars.len();
    let (disclosed_indexes, commitment_indexes) =
        disclosure_indexes(message_disclosures, L as u128)?;
    let generators = create_generators(suite, L as u128 + 1, &api_id)?;
    let mut default_rng = OsRandom;
    CoreProofGen(
        suite,
        PK,
        signature,
        &generators,
        header,
        ph,
        &message_scalars,
        &disclosed_indexes,
        &commitment_indexes,
        precomputed_rands,
        &api_id,
        rng.unwrap_or(&mut default_rng),
    )
}

/// Spec 3.5.4 ProofVerify. Validate the full schema before selecting disclosures.
#[allow(clippy::too_many_arguments)]
pub fn ProofVerify(
    suite: Ciphersuite,
    PK: &[u8],
    proof: &[u8],
    header: &[u8],
    ph: &[u8],
    disclosed_messages: &[Message],
    commitments: &[G1Projective],
    message_types: &[MessageType],
    message_disclosures: &[DisclosureState],
) -> BbsResult<()> {
    let api_id = suite.api_id();
    let L = message_disclosures.len();
    if message_types.len() != L || !valid_message_types(message_types) {
        return Err(INVALID);
    }
    let (disclosed_indexes, commitment_indexes) =
        disclosure_indexes(message_disclosures, L as u128)?;
    let R = disclosed_indexes.len();
    let N = commitment_indexes.len();
    if disclosed_messages.len() != R || commitments.len() != N {
        return Err(INVALID);
    }
    let disclosed_types = select(message_types, &disclosed_indexes)?;
    let disclosed_scalars =
        messages_to_scalars(suite, disclosed_messages, &disclosed_types, &api_id)?;

    let proof_result = octets_to_proof(proof)?;
    if proof_result.m_hats.len() != L - R || proof_result.N != N as u128 {
        return Err(INVALID);
    }
    if proof_result.commitments != commitments {
        return Err(INVALID);
    }

    let generators = create_generators(suite, L as u128 + 1, &api_id)?;
    // The proof was decoded (and its points subgroup-checked) above.
    core_proof_verify_decoded(
        suite,
        PK,
        &proof_result,
        &generators,
        header,
        ph,
        &disclosed_scalars,
        &disclosed_indexes,
        &commitment_indexes,
        commitments,
        &api_id,
    )
}

/// Spec 4.1.3 PrecomputeCommitment. Select types at the original message indexes.
pub fn PrecomputeCommitment(
    suite: Ciphersuite,
    committed_messages: &[Message],
    commitment_indexes: &[Index],
    message_types: &[MessageType],
    rng: Option<&mut dyn ScalarSource>,
) -> BbsResult<CommitmentOutput> {
    let api_id = suite.api_id();
    let L = message_types.len();
    if !valid_message_types(message_types)
        || !valid_indexes(commitment_indexes, L as u128)
        || committed_messages.len() != commitment_indexes.len()
    {
        return Err(INVALID);
    }
    let committed_scalars = messages_to_scalars(
        suite,
        committed_messages,
        &select(message_types, commitment_indexes)?,
        &api_id,
    )?;
    let N = committed_scalars.len();
    let mut default_rng = OsRandom;
    let commitment_rands = rng
        .unwrap_or(&mut default_rng)
        .calculate_random_scalars(N)?;
    let commitments = compute_commitments(suite, &committed_scalars, &commitment_rands, &api_id)?;
    Ok((commitments, commitment_rands))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::R;
    use crate::types::{OCTETS, SCALAR};
    use crate::utils::commitment_generators;

    struct RecordingSource {
        counts: Vec<usize>,
    }

    impl ScalarSource for RecordingSource {
        /// Spec 4.2.1: record each request, including an empty scalar request.
        fn calculate_random_scalars(&mut self, count: usize) -> BbsResult<Vec<ScalarInput>> {
            self.counts.push(count);
            Ok(vec![9u64.into(); count])
        }
    }

    /// Spec 3.4.1. Input checks precede hashing and its DST abort.
    #[test]
    fn keygen_validation_order() {
        for suite in [Ciphersuite::Sha256, Ciphersuite::Shake256] {
            assert_eq!(KeyGen(suite, &[0; 31], b"", Some(&[0; 256])), Err(INVALID));
            assert_eq!(KeyGen(suite, &[0; 32], &[0; 65536], None), Err(INVALID));
            let first = KeyGen(suite, &[0x42; 32], b"key info", None).unwrap();
            assert_eq!(
                first,
                KeyGen(suite, &[0x42; 32], b"key info", None).unwrap()
            );
            assert_eq!(SkToPk(first).unwrap().len(), 96);
        }
    }

    /// Spec 3.4.2. Secret keys must be canonical and nonzero.
    #[test]
    fn secret_key_rejection() {
        assert_eq!(SkToPk(0u64.into()), Err(INVALID));
        assert_eq!(SkToPk(ScalarInput(R)), Err(INVALID));
        assert_eq!(SkToPk(1u64.into()).unwrap(), point_to_octets_E2(&BP2()));
    }

    /// Spec 4.1.3: subset messages use types at their original schema indexes.
    #[test]
    fn precompute_original_index_types_and_empty_call() {
        for suite in [Ciphersuite::Sha256, Ciphersuite::Shake256] {
            let mut rng = RecordingSource { counts: vec![] };
            let (commitments, commitment_rands) = PrecomputeCommitment(
                suite,
                &[Message::Scalar(7u64.into())],
                &[1u64.into()],
                &[OCTETS, SCALAR],
                Some(&mut rng),
            )
            .unwrap();
            let (Y_0, Y_1) = commitment_generators(suite, &suite.api_id()).unwrap();
            assert_eq!(
                commitments,
                vec![Y_0 * bls12_381::Scalar::from(7u64) + Y_1 * bls12_381::Scalar::from(9u64)]
            );
            assert_eq!(commitment_rands, [9u64.into()]);
            assert_eq!(rng.counts, [1]);

            assert_eq!(
                PrecomputeCommitment(suite, &[], &[], &[], Some(&mut rng)).unwrap(),
                (vec![], vec![])
            );
            assert_eq!(rng.counts, [1, 0]);
        }
    }

    /// Spec 4.1.3: reject schema and index errors before consuming randomness.
    #[test]
    fn precompute_invalid_inputs_preserve_rng() {
        for suite in [Ciphersuite::Sha256, Ciphersuite::Shake256] {
            let mut rng = RecordingSource { counts: vec![] };
            assert_eq!(
                PrecomputeCommitment(
                    suite,
                    &[Message::Scalar(7u64.into())],
                    &[1u64.into()],
                    &[MessageType::Unknown("UNKNOWN".into()), SCALAR],
                    Some(&mut rng),
                ),
                Err(INVALID)
            );
            for commitment_indexes in [
                vec![1u64.into(), 0u64.into()],
                vec![0u64.into(), 0u64.into()],
                vec![2u64.into()],
                vec![Index::Other("1.5".into())],
                vec![],
            ] {
                assert_eq!(
                    PrecomputeCommitment(
                        suite,
                        &[Message::Scalar(7u64.into())],
                        &commitment_indexes,
                        &[SCALAR, SCALAR],
                        Some(&mut rng),
                    ),
                    Err(INVALID)
                );
            }
            assert!(rng.counts.is_empty());
        }
    }
}
