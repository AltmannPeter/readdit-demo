//! Spec 3.4–3.7: exceptional hash outputs through real interface and core calls.

use bls12_381::G1Projective;

use crate::core::{CoreProofGen, CoreProofVerify, CoreSign};
use crate::interface::{KeyGen, ProofGen, ProofVerify, Sign, SkToPk, Verify};
use crate::mock_rng::{ProfileRng, ScalarOverride};
use crate::params::Ciphersuite;
use crate::types::{
    COMMIT, DISCLOSE, HIDE, Index, Message, MessageType, OCTETS, ProofOutput, SCALAR, ScalarInput,
};
use crate::utils::hash_test_hook::HashOverride;
use crate::utils::{
    create_generators, hash_to_scalar, messages_to_scalars, octets_to_proof, octets_to_signature,
};
use crate::{BbsError, BbsResult, INVALID};

const SUITES: [Ciphersuite; 2] = [Ciphersuite::Sha256, Ciphersuite::Shake256];
const HEADER: &[u8] = b"exceptional hash tests";
const PH: &[u8] = b"presentation";
const KEY_MATERIAL: &[u8] = &[42; 32];
const KEY_INFO: &[u8] = b"key info";

struct Case {
    suite: Ciphersuite,
    SK: ScalarInput,
    PK: Vec<u8>,
    api: Vec<u8>,
    messages: Vec<Message>,
    message_types: Vec<MessageType>,
    scalars: Vec<ScalarInput>,
    generators: Vec<G1Projective>,
    signature: Vec<u8>,
}

impl Case {
    /// Spec 3.4–3.5: ordinary public key derivation and signing are the control.
    fn new(suite: Ciphersuite) -> Self {
        let SK = KeyGen(suite, KEY_MATERIAL, KEY_INFO, None).unwrap();
        let PK = SkToPk(SK).unwrap();
        let api = suite.api_id();
        let messages = vec![
            Message::Octets(b"disclosed octets".to_vec()),
            Message::Scalar(7u64.into()),
            Message::Scalar(11u64.into()),
        ];
        let message_types = vec![OCTETS, SCALAR, SCALAR];
        let scalars = messages_to_scalars(suite, &messages, &message_types, &api).unwrap();
        let generators = create_generators(suite, scalars.len() as u128 + 1, &api).unwrap();
        let signature = Sign(suite, SK, &PK, HEADER, &messages, &message_types).unwrap();
        Verify(suite, &PK, &signature, HEADER, &messages, &message_types).unwrap();
        Self {
            suite,
            SK,
            PK,
            api,
            messages,
            message_types,
            scalars,
            generators,
            signature,
        }
    }

    /// Spec 3.6.1, 3.7.4: distinguish domain/signature hashes from challenges.
    fn dst(&self, challenge: bool) -> Vec<u8> {
        let suffix: &[u8] = if challenge {
            b"COM_DIS_ETSI_PROOF_V1_H2S_"
        } else {
            b"H2S_"
        };
        [self.api.as_slice(), suffix].concat()
    }

    /// Spec 4.2.1 test machinery: a fresh deterministic stream per invocation.
    fn rng(&self, overrides: Vec<ScalarOverride>) -> ProfileRng {
        ProfileRng::new(
            self.suite,
            b"exceptional hash seed".to_vec(),
            b"exceptional hash randomness".to_vec(),
            overrides,
        )
    }

    /// Spec 3.5.1, 3.6.1: exercise both the public wrapper and direct core.
    fn sign(&self, core: bool) -> BbsResult<Vec<u8>> {
        if core {
            CoreSign(
                self.suite,
                self.SK,
                &self.PK,
                &self.generators,
                HEADER,
                &self.scalars,
                &self.api,
            )
        } else {
            Sign(
                self.suite,
                self.SK,
                &self.PK,
                HEADER,
                &self.messages,
                &self.message_types,
            )
        }
    }

    /// Spec 3.5.3, 3.6.3: use DISCLOSE, COMMIT and HIDE with actual openings.
    fn generate(&self, core: bool, rng: &mut ProfileRng) -> BbsResult<ProofOutput> {
        if core {
            CoreProofGen(
                self.suite,
                &self.PK,
                &self.signature,
                &self.generators,
                HEADER,
                PH,
                &self.scalars,
                &[Index::from(0)],
                &[Index::from(1)],
                None,
                &self.api,
                rng,
            )
        } else {
            ProofGen(
                self.suite,
                &self.PK,
                &self.signature,
                HEADER,
                PH,
                &self.messages,
                &self.message_types,
                &[DISCLOSE, COMMIT, HIDE],
                None,
                Some(rng),
            )
        }
    }

    /// Spec 3.5.4, 3.6.4: verify a valid proof with its nonempty commitment vector.
    fn verify(&self, core: bool, proof: &[u8]) -> BbsResult<()> {
        let commitments = octets_to_proof(proof).unwrap().commitments;
        if core {
            CoreProofVerify(
                self.suite,
                &self.PK,
                proof,
                &self.generators,
                HEADER,
                PH,
                &self.scalars[..1],
                &[Index::from(0)],
                &[Index::from(1)],
                &commitments,
                &self.api,
            )
        } else {
            ProofVerify(
                self.suite,
                &self.PK,
                proof,
                HEADER,
                PH,
                &self.messages[..1],
                &commitments,
                &self.message_types,
                &[DISCLOSE, COMMIT, HIDE],
            )
        }
    }
}

/// Spec 3.4.1: a zero hash cannot become an SK or a partial keypair.
#[test]
fn keygen_rejects_zero_hash() {
    for suite in SUITES {
        let default_dst = [suite.ciphersuite_id(), b"KEYGEN_DST_"].concat();
        for key_dst in [None, Some(b"custom key dst".as_slice())] {
            let baseline = KeyGen(suite, KEY_MATERIAL, KEY_INFO, key_dst).unwrap();
            assert_ne!(baseline, 0u64.into());
            let target = key_dst.unwrap_or(&default_dst).to_vec();
            {
                let hook = HashOverride::new(suite, target, 1, Ok(0u64.into()));
                assert_eq!(KeyGen(suite, KEY_MATERIAL, KEY_INFO, key_dst), Err(INVALID));
                assert_eq!(hook.counts(), (1, 1));
            }
            assert_eq!(KeyGen(suite, KEY_MATERIAL, KEY_INFO, key_dst), Ok(baseline));
        }
    }
}

/// Spec 3.5.1, 3.6.1: e=0 and e=-SK reject after the genuine domain hash.
#[test]
fn signing_rejects_exceptional_hashes() {
    for suite in SUITES {
        let case = Case::new(suite);
        for core in [false, true] {
            assert_eq!(case.sign(core), Ok(case.signature.clone()));
            for e in [
                0u64.into(),
                ScalarInput::from(-case.SK.to_scalar().unwrap()),
            ] {
                {
                    // calculate_domain is invocation 1 under this same DST.
                    let hook = HashOverride::new(suite, case.dst(false), 2, Ok(e));
                    assert_eq!(case.sign(core), Err(INVALID));
                    assert_eq!(hook.counts(), (2, 1));
                }
                assert_eq!(case.sign(core), Ok(case.signature.clone()));
            }
        }
    }
}

/// Spec 3.5.3, 3.6.3: zero challenge returns INVALID after all three RNG calls.
#[test]
fn proof_generation_rejects_zero_challenge_without_partial_output() {
    for suite in SUITES {
        let case = Case::new(suite);
        for core in [false, true] {
            let baseline = case.generate(core, &mut case.rng(vec![])).unwrap();
            assert_ne!(octets_to_proof(&baseline.0).unwrap().challenge, 0u64.into());
            assert_eq!(baseline.1.0.len(), 1);
            assert_eq!(baseline.1.1.len(), 1);
            case.verify(core, &baseline.0).unwrap();
            {
                let hook = HashOverride::new(suite, case.dst(true), 1, Ok(0u64.into()));
                let mut rng = case.rng(vec![]);
                assert_eq!(case.generate(core, &mut rng), Err(INVALID));
                assert_eq!(hook.counts(), (1, 1));
                assert_eq!(
                    rng.calls.iter().map(Vec::len).collect::<Vec<_>>(),
                    [1, 7, 1]
                );
            }
            assert_eq!(case.generate(core, &mut case.rng(vec![])), Ok(baseline));
        }
    }
}

/// Spec 3.5.4, 3.6.4: a zero recomputed challenge rejects a valid encoded proof.
#[test]
fn proof_verification_rejects_zero_recomputed_challenge() {
    for suite in SUITES {
        let case = Case::new(suite);
        let baseline = case.generate(false, &mut case.rng(vec![])).unwrap();
        assert_ne!(octets_to_proof(&baseline.0).unwrap().challenge, 0u64.into());
        for core in [false, true] {
            case.verify(core, &baseline.0).unwrap();
            {
                let hook = HashOverride::new(suite, case.dst(true), 1, Ok(0u64.into()));
                assert_eq!(case.verify(core, &baseline.0), Err(INVALID));
                assert_eq!(hook.counts(), (1, 1));
            }
            case.verify(core, &baseline.0).unwrap();
        }
    }
}

/// Spec 3.6.3–3.7.4 / SI-002: subroutine errors propagate through both boundaries.
#[test]
fn proof_subroutine_hash_errors_propagate() {
    for suite in SUITES {
        let case = Case::new(suite);
        let baseline = case.generate(false, &mut case.rng(vec![])).unwrap();
        for core in [false, true] {
            for challenge in [false, true] {
                for error in [INVALID, BbsError::Abort("injected hash failure")] {
                    {
                        // Domain call 1 belongs to mandatory CoreVerify; call 2 to ProofInit.
                        let invocation = if challenge { 1 } else { 2 };
                        let hook =
                            HashOverride::new(suite, case.dst(challenge), invocation, Err(error));
                        let mut rng = case.rng(vec![]);
                        assert_eq!(case.generate(core, &mut rng), Err(error));
                        assert_eq!(hook.counts(), (invocation, 1));
                        assert_eq!(rng.calls.len(), 3);
                    }
                    {
                        // The verifier's domain hash is inside ProofVerifyInit.
                        let hook = HashOverride::new(suite, case.dst(challenge), 1, Err(error));
                        assert_eq!(case.verify(core, &baseline.0), Err(error));
                        assert_eq!(hook.counts(), (1, 1));
                    }
                }
            }
            case.verify(core, &baseline.0).unwrap();
        }
    }
}

/// Spec 3.6.3, 3.7.2 / SI-002: a failed final encoding never returns openings.
#[test]
fn proof_finalize_error_has_no_partial_output() {
    for suite in SUITES {
        let case = Case::new(suite);
        let e = octets_to_signature(&case.signature)
            .unwrap()
            .e
            .to_scalar()
            .unwrap();
        for core in [false, true] {
            let mut rng = case.rng(vec![ScalarOverride {
                call: 2,
                index: 2,
                value: (-e).into(),
            }]);
            {
                // c=1 gives e_hat = -e + e*c = 0, rejected by ProofFinalize's encoding.
                let hook = HashOverride::new(suite, case.dst(true), 1, Ok(1u64.into()));
                assert_eq!(case.generate(core, &mut rng), Err(INVALID));
                assert_eq!(hook.counts(), (1, 1));
                assert_eq!(
                    rng.calls.iter().map(Vec::len).collect::<Vec<_>>(),
                    [1, 7, 1]
                );
            }
            let baseline = case.generate(core, &mut case.rng(vec![])).unwrap();
            case.verify(core, &baseline.0).unwrap();
        }
    }
}

/// Spec 4.2.2 test machinery: guards, scope cleanup and thread isolation hold.
#[test]
fn hash_override_is_scoped_and_preserves_guards() {
    for suite in SUITES {
        let dst = b"scoped hash dst";
        let baseline = hash_to_scalar(suite, b"msg", dst).unwrap();
        let other_suite = if suite == SUITES[0] {
            SUITES[1]
        } else {
            SUITES[0]
        };
        let other_baseline = hash_to_scalar(other_suite, b"msg", dst).unwrap();
        let other_dst_baseline = hash_to_scalar(suite, b"msg", b"other dst").unwrap();
        {
            let hook = HashOverride::new(suite, dst.to_vec(), 2, Ok(0u64.into()));
            assert_eq!(hash_to_scalar(other_suite, b"msg", dst), Ok(other_baseline));
            assert_eq!(
                hash_to_scalar(suite, b"msg", b"other dst"),
                Ok(other_dst_baseline)
            );
            assert_eq!(
                std::thread::spawn(move || hash_to_scalar(suite, b"msg", dst))
                    .join()
                    .unwrap(),
                Ok(baseline)
            );
            assert_eq!(hook.counts(), (0, 0));
            assert_eq!(hash_to_scalar(suite, b"msg", dst), Ok(baseline));
            assert_eq!(hash_to_scalar(suite, b"msg", dst), Ok(0u64.into()));
            assert_eq!(hash_to_scalar(suite, b"msg", dst), Ok(baseline));
            assert_eq!(hook.counts(), (3, 1));
        }
        assert_eq!(hash_to_scalar(suite, b"msg", dst), Ok(baseline));
        {
            let oversized_dst = vec![0; 256];
            let hook = HashOverride::new(suite, oversized_dst.clone(), 1, Ok(0u64.into()));
            assert_eq!(
                hash_to_scalar(suite, b"msg", &oversized_dst),
                Err(BbsError::Abort("hash_to_scalar DST exceeds 255 octets"))
            );
            assert_eq!(hook.counts(), (0, 0));
        }
        let unwound = std::panic::catch_unwind(|| {
            let _hook = HashOverride::new(suite, dst.to_vec(), 1, Ok(0u64.into()));
            panic!("exercise RAII hash cleanup");
        });
        assert!(unwound.is_err());
        assert_eq!(hash_to_scalar(suite, b"msg", dst), Ok(baseline));
    }
}
