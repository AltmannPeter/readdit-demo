//! Spec 3.5–3.7: independent M2 cases; no supplied profile fixtures are read.
#![allow(non_snake_case)]
use bbs_cd::interface::{
    KeyGen, PrecomputeCommitment, ProofGen, ProofVerify, Sign, SkToPk, Verify,
};
use bbs_cd::params::Ciphersuite;
use bbs_cd::types::{
    COMMIT, DISCLOSE, DisclosureState, HIDE, Message, OCTETS, SCALAR, ScalarInput, ScalarSource,
};
use bbs_cd::utils::{compute_commitments, messages_to_scalars, octets_to_proof, proof_to_octets};
use bbs_cd::{BbsError, BbsResult, INVALID};
use bls12_381::{G1Projective, Scalar};

/// Spec 4.2.1: test-only advancing scalar source, with observable zero-count calls.
struct CountingSource {
    next: u64,
    calls: Vec<usize>,
    zero_mask: Option<usize>,
}
impl CountingSource {
    /// Spec 4.2.1: deterministic values for round trips, not profile fixture machinery.
    fn new() -> Self {
        Self {
            next: 17,
            calls: Vec::new(),
            zero_mask: None,
        }
    }
}
impl ScalarSource for CountingSource {
    /// Spec 4.2.1: advance over every invocation and each returned value.
    fn calculate_random_scalars(&mut self, count: usize) -> BbsResult<Vec<ScalarInput>> {
        self.calls.push(count);
        self.next += 1;
        let mut values: Vec<_> = (0..count)
            .map(|_| {
                self.next += 1;
                self.next.into()
            })
            .collect();
        if count >= 5 {
            if let Some(i) = self.zero_mask {
                values[i] = 0u64.into();
            }
        }
        Ok(values)
    }
}

/// Spec 3.5, 4.1.3: all required disclosure patterns, original-index typing and precomputation.
fn round_trips(suite: Ciphersuite) {
    let SK = KeyGen(suite, &[0x73; 32], b"M2", None).unwrap();
    let PK = SkToPk(SK).unwrap();
    let source_messages = [
        Message::Octets(b"first".to_vec()),
        Message::Scalar(0u64.into()),
        Message::Octets(b"third".to_vec()),
        Message::Scalar(19u64.into()),
    ];
    let source_types = [OCTETS, SCALAR, OCTETS, SCALAR];
    let patterns = [
        vec![HIDE; 4],
        vec![DISCLOSE; 4],
        vec![COMMIT; 4],
        vec![COMMIT, DISCLOSE, HIDE, COMMIT],
        vec![],
        vec![DISCLOSE, HIDE, DISCLOSE, HIDE],
        vec![HIDE, COMMIT, DISCLOSE, HIDE],
    ];
    for states in patterns {
        let L = states.len();
        let messages = &source_messages[..L];
        let types = &source_types[..L];
        let signature = Sign(suite, SK, &PK, b"header", messages, types).unwrap();
        Verify(suite, &PK, &signature, b"header", messages, types).unwrap();
        let mut rng = CountingSource::new();
        let (proof, (committed_messages, rands)) = ProofGen(
            suite,
            &PK,
            &signature,
            b"header",
            b"context",
            messages,
            types,
            &states,
            None,
            Some(&mut rng),
        )
        .unwrap();
        let parsed = octets_to_proof(&proof).unwrap();
        let N = states.iter().filter(|s| **s == COMMIT).count();
        let R = states.iter().filter(|s| **s == DISCLOSE).count();
        let U = L - R;
        assert_eq!(rng.calls, [N, 5 + U, N]);
        assert_eq!(parsed.N, N as u128);
        assert_eq!(proof.len(), 280 + U * 32 + N * 80);
        assert_eq!(&proof[..8], &(N as u64).to_be_bytes());
        assert_eq!(proof_to_octets(&parsed).unwrap(), proof);
        assert_eq!(
            compute_commitments(suite, &committed_messages, &rands, &suite.api_id()).unwrap(),
            parsed.commitments
        );
        let disclosed: Vec<_> = messages
            .iter()
            .zip(&states)
            .filter(|(_, s)| **s == DISCLOSE)
            .map(|(m, _)| m.clone())
            .collect();
        ProofVerify(
            suite,
            &PK,
            &proof,
            b"header",
            b"context",
            &disclosed,
            &parsed.commitments,
            types,
            &states,
        )
        .unwrap();
        assert_eq!(
            ProofVerify(
                suite,
                &PK,
                &proof,
                b"header",
                b"changed context",
                &disclosed,
                &parsed.commitments,
                types,
                &states
            ),
            Err(INVALID)
        );
        assert_eq!(
            ProofVerify(
                suite,
                &PK,
                &proof,
                b"wrong header",
                b"context",
                &disclosed,
                &parsed.commitments,
                types,
                &states
            ),
            Err(INVALID)
        );
        if N > 0 {
            let mut wrong = parsed.commitments.clone();
            wrong[0] += G1Projective::generator();
            assert_eq!(
                ProofVerify(
                    suite, &PK, &proof, b"header", b"context", &disclosed, &wrong, types, &states
                ),
                Err(INVALID)
            );
            wrong[0] = G1Projective::identity();
            assert_eq!(
                ProofVerify(
                    suite, &PK, &proof, b"header", b"context", &disclosed, &wrong, types, &states
                ),
                Err(INVALID)
            );
            let mut altered = parsed.clone();
            altered.commitments[0] += G1Projective::generator();
            let altered_bytes = proof_to_octets(&altered).unwrap();
            assert_eq!(
                ProofVerify(
                    suite,
                    &PK,
                    &altered_bytes,
                    b"header",
                    b"context",
                    &disclosed,
                    &altered.commitments,
                    types,
                    &states
                ),
                Err(INVALID)
            );
        }
        let indexes: Vec<_> = states
            .iter()
            .enumerate()
            .filter(|(_, s)| **s == COMMIT)
            .map(|(i, _)| (i as u64).into())
            .collect();
        let committed_inputs: Vec<_> = messages
            .iter()
            .zip(&states)
            .filter(|(_, s)| **s == COMMIT)
            .map(|(m, _)| m.clone())
            .collect();
        let mut pre_rng = CountingSource::new();
        let (pre_points, pre_rands) = PrecomputeCommitment(
            suite,
            &committed_inputs,
            &indexes,
            types,
            Some(&mut pre_rng),
        )
        .unwrap();
        assert_eq!(pre_rng.calls, [N]);
        assert_eq!(pre_rands, rands);
        assert_eq!(pre_points, parsed.commitments);
        let (pre_proof, pre_info) = ProofGen(
            suite,
            &PK,
            &signature,
            b"header",
            b"context",
            messages,
            types,
            &states,
            Some(&pre_rands),
            Some(&mut pre_rng),
        )
        .unwrap();
        assert_eq!(pre_rng.calls, [N, 5 + U, N]);
        assert_eq!(pre_proof, proof);
        assert_eq!(pre_info, (committed_messages, rands));
        let next_proof = ProofGen(
            suite,
            &PK,
            &signature,
            b"header",
            b"second context",
            messages,
            types,
            &states,
            None,
            Some(&mut rng),
        )
        .unwrap()
        .0;
        assert_ne!(octets_to_proof(&next_proof).unwrap().A_bar, parsed.A_bar);
        // Fixed malformed source output is rejected without retrying or returning openings.
        for mask in [0, 1] {
            let mut bad_rng = CountingSource::new();
            bad_rng.zero_mask = Some(mask);
            assert_eq!(
                ProofGen(
                    suite,
                    &PK,
                    &signature,
                    b"header",
                    b"context",
                    messages,
                    types,
                    &states,
                    None,
                    Some(&mut bad_rng)
                ),
                Err(INVALID)
            );
            assert_eq!(bad_rng.calls, [N, 5 + U, N]);
        }
    }
}

/// Spec 3.5–3.7: seven patterns under SHA-256.
#[test]
fn profile_sha256_roundtrips() {
    round_trips(Ciphersuite::Sha256);
}
/// Spec 3.5–3.7: seven patterns under SHAKE-256.
#[test]
fn profile_shake256_roundtrips() {
    round_trips(Ciphersuite::Shake256);
}

/// Spec 3.6.3: invalid inputs and ABORT never produce partial output or bypass signature validation.
#[test]
fn proof_validation_and_rng_failures() {
    struct FailingSource {
        calls: usize,
    }
    impl ScalarSource for FailingSource {
        fn calculate_random_scalars(&mut self, _: usize) -> BbsResult<Vec<ScalarInput>> {
            self.calls += 1;
            Err(BbsError::Abort("injected RNG failure"))
        }
    }
    for suite in [Ciphersuite::Sha256, Ciphersuite::Shake256] {
        let SK = 7u64.into();
        let PK = SkToPk(SK).unwrap();
        let messages = [Message::Scalar(4u64.into()), Message::Octets(b"x".to_vec())];
        let types = [SCALAR, OCTETS];
        let states = [COMMIT, DISCLOSE];
        let signature = Sign(suite, SK, &PK, b"", &messages, &types).unwrap();
        let mut rng = FailingSource { calls: 0 };
        assert_eq!(
            ProofGen(
                suite,
                &PK,
                &signature,
                b"bad",
                b"",
                &messages,
                &types,
                &states,
                None,
                Some(&mut rng)
            ),
            Err(INVALID)
        );
        assert_eq!(rng.calls, 0);
        assert!(matches!(
            ProofGen(
                suite,
                &PK,
                &signature,
                b"",
                b"",
                &messages,
                &types,
                &states,
                None,
                Some(&mut rng)
            ),
            Err(BbsError::Abort(_))
        ));
        assert_eq!(rng.calls, 1);
        assert_eq!(
            ProofGen(
                suite,
                &PK,
                &signature,
                b"",
                b"",
                &messages,
                &types,
                &states,
                Some(&[]),
                Some(&mut rng)
            ),
            Err(INVALID)
        );
        assert_eq!(rng.calls, 1);
        let bad_states = [DisclosureState::Unknown("SHOW".into()), DISCLOSE];
        assert_eq!(
            ProofGen(
                suite,
                &PK,
                &signature,
                b"",
                b"",
                &messages,
                &types,
                &bad_states,
                None,
                Some(&mut rng)
            ),
            Err(INVALID)
        );
        assert_eq!(rng.calls, 1);
        let mut good = CountingSource::new();
        let (proof, _) = ProofGen(
            suite,
            &PK,
            &signature,
            b"",
            b"",
            &messages,
            &types,
            &states,
            None,
            Some(&mut good),
        )
        .unwrap();
        let parsed = octets_to_proof(&proof).unwrap();
        let wrong_types = [
            bbs_cd::types::MessageType::Unknown("UNKNOWN".into()),
            OCTETS,
        ];
        assert_eq!(
            ProofVerify(
                suite,
                &PK,
                &proof,
                b"",
                b"",
                &messages[1..],
                &parsed.commitments,
                &wrong_types,
                &states
            ),
            Err(INVALID)
        );
        // A scalar at a disclosed OCTETS position cannot borrow the type at index zero.
        assert_eq!(
            ProofVerify(
                suite,
                &PK,
                &proof,
                b"",
                b"",
                &messages[..1],
                &parsed.commitments,
                &types,
                &states
            ),
            Err(INVALID)
        );
        let mut changed = parsed.clone();
        changed.challenge = (changed.challenge.to_scalar().unwrap() + Scalar::one()).into();
        assert_eq!(
            ProofVerify(
                suite,
                &PK,
                &proof_to_octets(&changed).unwrap(),
                b"",
                b"",
                &messages[1..],
                &parsed.commitments,
                &types,
                &states
            ),
            Err(INVALID)
        );
        let scalars = messages_to_scalars(suite, &messages, &types, &suite.api_id()).unwrap();
        assert_eq!(scalars[0], 4u64.into());
    }
}

/// Spec 3.6.3 and SI-002: a zero final response rejects the whole generation result.
#[test]
fn zero_response_propagates_without_partial_output() {
    struct ZeroMessageMask {
        calls: Vec<usize>,
    }
    impl ScalarSource for ZeroMessageMask {
        /// Spec 4.2.1: inject a zero message mask while retaining nonzero r1 and r2.
        fn calculate_random_scalars(&mut self, count: usize) -> BbsResult<Vec<ScalarInput>> {
            self.calls.push(count);
            let mut values = vec![3u64.into(); count];
            if count == 6 {
                values[5] = 0u64.into();
            }
            Ok(values)
        }
    }
    for suite in [Ciphersuite::Sha256, Ciphersuite::Shake256] {
        let PK = SkToPk(7u64.into()).unwrap();
        let messages = [Message::Scalar(0u64.into())];
        let signature = Sign(suite, 7u64.into(), &PK, b"", &messages, &[SCALAR]).unwrap();
        let mut rng = ZeroMessageMask { calls: vec![] };
        assert_eq!(
            ProofGen(
                suite,
                &PK,
                &signature,
                b"",
                b"",
                &messages,
                &[SCALAR],
                &[COMMIT],
                None,
                Some(&mut rng)
            ),
            Err(INVALID)
        );
        assert_eq!(rng.calls, [1, 6, 1]);
    }
}
