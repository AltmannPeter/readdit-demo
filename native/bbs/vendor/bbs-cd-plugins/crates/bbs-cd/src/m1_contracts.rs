//! Spec Sections 1.4, 3.6–3.7, 4.1–4.2: independent contract tests.
use crate::core::{CoreSign, CoreVerify, ProofInit};
use crate::helpers::{dot, valid_generators, valid_indexes};
use crate::interface::SkToPk;
use crate::params::{Ciphersuite, MAX_MESSAGES, R};
use crate::primitives::{expand_message, hash_to_curve_g1, point_to_octets_E1};
use crate::types::{Index, ScalarInput};
use crate::utils::{Field, create_generators, octets_to_signature, serialize};
use crate::{BbsError, INVALID};
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

/// Spec 4.2.4.1 and 4.2.4.6: generic serialization allows identity, not torsion.
#[test]
fn serializer_validates_group_membership() {
    let identity1 = G1Projective::identity();
    let identity2 = G2Projective::identity();
    assert_eq!(
        serialize(&[Field::G1(&identity1), Field::G2(&identity2)])
            .unwrap()
            .len(),
        144
    );
    let mut bytes = [0; 48];
    bytes[0] = 0x80;
    let torsion = G1Projective::from(
        Option::<G1Affine>::from(G1Affine::from_compressed_unchecked(&bytes)).unwrap(),
    );
    assert_eq!(serialize(&[Field::G1(&torsion)]), Err(INVALID));
    let torsion2 = (0..=255u8)
        .find_map(|x| {
            let mut bytes = [0; 96];
            bytes[0] = 0x80;
            bytes[95] = x;
            Option::<G2Affine>::from(G2Affine::from_compressed_unchecked(&bytes))
                .filter(|p| !bool::from(p.is_torsion_free()))
        })
        .unwrap();
    assert_eq!(
        serialize(&[Field::G2(&G2Projective::from(torsion2))]),
        Err(INVALID)
    );
}

/// Spec 1.5.2 / BBS-12 7.2: independently derive fixed P1 outside create_generators.
#[test]
fn fixed_p1_derivation() {
    for suite in [Ciphersuite::Sha256, Ciphersuite::Shake256] {
        let id = suite.ciphersuite_id();
        let seed_dst = [id, b"H2G_HM2S_SIG_GENERATOR_SEED_"].concat();
        let generator_dst = [id, b"H2G_HM2S_SIG_GENERATOR_DST_"].concat();
        let generator_seed = [id, b"H2G_HM2S_BP_MESSAGE_GENERATOR_SEED"].concat();
        let v = expand_message(suite, &generator_seed, &seed_dst, 48).unwrap();
        let v = expand_message(
            suite,
            &[v.as_slice(), &1u64.to_be_bytes()].concat(),
            &seed_dst,
            48,
        )
        .unwrap();
        assert_eq!(
            hash_to_curve_g1(suite, &v, &generator_dst).unwrap(),
            suite.P1()
        );
    }
}

/// Spec 4.1.4 / Section 5: reject malformed indexes without sorting or coercion.
#[test]
fn indexes_preserve_invalid_values() {
    assert!(valid_indexes(&[], 0));
    assert!(valid_indexes(&[0u64.into(), 2u64.into()], 3));
    for indexes in [
        vec![1u64.into(), 1u64.into()],
        vec![2u64.into(), 1u64.into()],
        vec![3u64.into()],
        vec![Index::Other("1.5".into())],
        vec![Index::Other("-1".into())],
    ] {
        assert!(!valid_indexes(&indexes, 3));
    }
    assert!(!valid_indexes(&[], MAX_MESSAGES + 1));
}

/// Spec 3.6.1–3.6.2: round-trip edge counts and reject mismatched keys/inputs.
#[test]
fn signature_contracts_both_suites() {
    for suite in [Ciphersuite::Sha256, Ciphersuite::Shake256] {
        let SK = ScalarInput::from(42);
        let PK = SkToPk(SK).unwrap();
        let api = suite.api_id();
        for messages in [
            vec![],
            vec![0u64.into()],
            vec![0u64.into(), ScalarInput::from(-Scalar::one()), 7u64.into()],
        ] {
            let generators = create_generators(suite, messages.len() as u128 + 1, &api).unwrap();
            let signature =
                CoreSign(suite, SK, &PK, &generators, b"header", &messages, &api).unwrap();
            assert_eq!(
                CoreVerify(
                    suite,
                    &PK,
                    &signature,
                    &generators,
                    b"header",
                    &messages,
                    &api
                ),
                Ok(())
            );
            assert_eq!(
                CoreVerify(
                    suite,
                    &PK,
                    &signature,
                    &generators,
                    b"other",
                    &messages,
                    &api
                ),
                Err(INVALID)
            );
            let wrong_pk = SkToPk(43u64.into()).unwrap();
            assert_eq!(
                CoreSign(
                    suite,
                    SK,
                    &wrong_pk,
                    &generators,
                    b"header",
                    &messages,
                    &api
                ),
                Err(INVALID)
            );
            assert_eq!(
                CoreVerify(
                    suite,
                    &wrong_pk,
                    &signature,
                    &generators,
                    b"header",
                    &messages,
                    &api
                ),
                Err(INVALID)
            );
            let mut extra = signature.clone();
            extra.push(0);
            assert_eq!(
                CoreVerify(suite, &PK, &extra, &generators, b"header", &messages, &api),
                Err(INVALID)
            );
        }
        let g = create_generators(suite, 2, &api).unwrap();
        assert_eq!(
            CoreSign(suite, ScalarInput(R), &PK, &g, b"", &[1u64.into()], &api),
            Err(INVALID)
        );
        assert_eq!(
            CoreSign(suite, SK, &PK, &g, b"", &[ScalarInput(R)], &api),
            Err(INVALID)
        );
        assert_eq!(
            CoreSign(suite, SK, &PK, &g, b"", &[ScalarInput([0xff; 32])], &api),
            Err(INVALID)
        );
        let mut duplicate = g.clone();
        duplicate[1] = duplicate[0];
        assert!(!valid_generators(suite, &duplicate, 1));
        assert!(!valid_generators(suite, &[suite.P1()], 0));
        assert_eq!(dot(&[], &[]).unwrap(), G1Projective::identity());
    }
}

/// Spec 3.6.1–3.6.2: earlier invalid inputs prevent later hash DST aborts.
#[test]
fn core_check_order() {
    let suite = Ciphersuite::Sha256;
    let PK = SkToPk(1u64.into()).unwrap();
    let generators = [G1Projective::generator()];
    assert_eq!(
        CoreSign(suite, 0u64.into(), b"invalid", &[], b"", &[], &[0; 256]),
        Err(INVALID)
    );
    assert_eq!(
        CoreVerify(suite, &PK, b"invalid", &generators, b"", &[], &[0; 256]),
        Err(INVALID)
    );
    assert!(matches!(
        CoreSign(suite, 1u64.into(), &PK, &generators, b"", &[], &[0; 256]),
        Err(BbsError::Abort(_))
    ));
}

/// Spec 3.7.1: preserve ABORT vs INVALID ordering and zero-mask identity allowance.
#[test]
fn proof_init_contracts_both_suites() {
    for suite in [Ciphersuite::Sha256, Ciphersuite::Shake256] {
        let SK = ScalarInput::from(3);
        let PK = SkToPk(SK).unwrap();
        let api = suite.bbs_api_id();
        let generators = create_generators(suite, 2, &api).unwrap();
        let messages = [8u64.into()];
        let octets = CoreSign(suite, SK, &PK, &generators, b"", &messages, &api).unwrap();
        let signature = octets_to_signature(&octets).unwrap();
        let masks = [
            1u64.into(),
            2u64.into(),
            0u64.into(),
            0u64.into(),
            0u64.into(),
            0u64.into(),
        ];
        let valid = ProofInit(
            suite,
            &PK,
            &signature,
            &generators,
            &masks,
            b"",
            &messages,
            &[0u64.into()],
            &[],
            &[],
            &api,
        )
        .unwrap();
        assert_eq!(valid.T1, G1Projective::identity());
        assert_eq!(valid.T2, G1Projective::identity());
        assert_eq!(point_to_octets_E1(&valid.T1)[0], 0xc0);
        let aborted = ProofInit(
            suite,
            &PK,
            &signature,
            &generators,
            &[],
            b"",
            &messages,
            &[1u64.into()],
            &[],
            &[],
            &api,
        )
        .unwrap_err();
        assert!(matches!(aborted, BbsError::Abort(_)));
        let invalid = ProofInit(
            suite,
            &PK,
            &signature,
            &[],
            &[],
            b"",
            &messages,
            &[1u64.into()],
            &[],
            &[],
            &api,
        )
        .unwrap_err();
        assert_eq!(invalid, INVALID);
        let mut zero = masks;
        zero[0] = 0u64.into();
        assert_eq!(
            ProofInit(
                suite,
                &PK,
                &signature,
                &generators,
                &zero,
                b"",
                &messages,
                &[0u64.into()],
                &[],
                &[],
                &api
            )
            .unwrap_err(),
            INVALID
        );
        assert_eq!(
            ProofInit(
                suite,
                &PK,
                &signature,
                &generators,
                &masks,
                b"",
                &messages,
                &[0u64.into()],
                &[1u64.into()],
                &[1u64.into()],
                &api
            )
            .unwrap_err(),
            INVALID
        );
        // The commitment mask shares m_tilde at the original undisclosed index.
        let committed = ProofInit(
            suite,
            &PK,
            &signature,
            &generators,
            &masks,
            b"",
            &messages,
            &[0u64.into()],
            &[0u64.into()],
            &[0u64.into()],
            &api,
        )
        .unwrap();
        assert_eq!(committed.C_tildes, [G1Projective::identity()]);
    }
}
