//! Equivalence and boundary tests for the performance changes:
//!
//! * variable-time multiplication on the holder and verifier paths
//!   (`helpers::mul_vartime`, wNAF; `helpers::msm_vartime`, Straus with
//!   unsigned 4-bit windows and complete projective addition);
//! * subgroup checks done once per point (`valid_generators_cached` and the
//!   `*_in_g1` internal variants).
//!
//! The fast paths must give the same results as the code they replace, and
//! every public entry point must still reject points outside G1.
use crate::INVALID;
use crate::core::{CoreProofGen, CoreProofVerify, CoreSign, CoreVerify};
use crate::helpers::{
    dot, in_g1, msm_vartime, mul_vartime, valid_generators, valid_generators_cached,
};
use crate::interface::SkToPk;
use crate::params::Ciphersuite;
use crate::types::{Index, OsRandom, Proof, ScalarInput};
use crate::utils::{
    calculate_domain, calculate_domain_in_g1, commitment_generators, create_generators,
    octets_to_proof, presentation_context, presentation_context_in_g1, proof_to_octets,
    proof_to_octets_in_g1, valid_proof_tuple, valid_proof_tuple_in_g1,
};
use bls12_381::{G1Affine, G1Projective, Scalar};

const SUITES: [Ciphersuite; 2] = [Ciphersuite::Sha256, Ciphersuite::Shake256];

/// A point on E1 of order 3 (x = 0, y = 2): on the curve, outside G1.
fn torsion_point() -> G1Projective {
    let mut bytes = [0; 48];
    bytes[0] = 0x80;
    let p = Option::<G1Affine>::from(G1Affine::from_compressed_unchecked(&bytes)).unwrap();
    assert!(bool::from(p.is_on_curve()) && !bool::from(p.is_torsion_free()));
    G1Projective::from(p)
}

/// Deterministic pseudo-random scalars (test only).
fn scalars(n: usize, seed: u64) -> Vec<Scalar> {
    (0..n as u64)
        .map(|i| {
            let mut wide = [0u8; 64];
            wide[..8]
                .copy_from_slice(&(seed ^ (i.wrapping_mul(0x9e37_79b9_7f4a_7c15))).to_le_bytes());
            wide[8..16].copy_from_slice(&i.to_le_bytes());
            wide[16] = 0xa5;
            Scalar::from_bytes_wide(&wide).square() + Scalar::from(i)
        })
        .collect()
}

#[test]
fn mul_vartime_equals_constant_time_multiplication() {
    let g = G1Projective::generator();
    let mut cases: Vec<(G1Projective, Scalar)> = Vec::new();
    for (i, s) in scalars(40, 7).into_iter().enumerate() {
        cases.push((g * Scalar::from(i as u64 + 2), s));
    }
    let edge = [
        Scalar::zero(),
        Scalar::one(),
        -Scalar::one(),
        Scalar::from(2u64),
        -Scalar::from(2u64),
        Scalar::from(u64::MAX),
    ];
    for s in edge {
        cases.push((g, s));
        cases.push((G1Projective::identity(), s));
        cases.push((g * Scalar::from(3u64), s));
    }
    // a point outside G1: same group-law result as the reference
    for s in edge.iter().chain(scalars(5, 9).iter()) {
        cases.push((torsion_point(), *s));
    }
    for (p, s) in cases {
        assert_eq!(mul_vartime(&p, &s), p * s);
    }
}

/// Reference: separate constant-time multiplications, summed.
fn naive_msm(points: &[G1Projective], scalars: &[Scalar]) -> G1Projective {
    points
        .iter()
        .zip(scalars)
        .fold(G1Projective::identity(), |acc, (p, s)| acc + p * s)
}

/// Scalars chosen to stress the window decomposition: 0, 1, small values,
/// r - 1, r - 2, every power of two with its neighbours, every digit value
/// in every window, and dense bit patterns.
fn adversarial_scalars() -> Vec<Scalar> {
    let mut v = vec![
        Scalar::zero(),
        Scalar::one(),
        Scalar::from(2u64),
        Scalar::from(15u64),
        Scalar::from(16u64),
        Scalar::from(17u64),
        Scalar::from(u64::MAX),
        -Scalar::one(),
        -Scalar::from(2u64),
        -Scalar::from(16u64),
    ];
    let mut pow = Scalar::one();
    for _ in 0..256 {
        v.push(pow);
        v.push(pow + Scalar::one());
        v.push(pow - Scalar::one());
        pow = pow.double();
    }
    let mut window = Scalar::one(); // 16^w
    for _ in 0..64 {
        for d in 1..16u64 {
            v.push(window * Scalar::from(d));
        }
        window *= Scalar::from(16u64);
    }
    for byte in [0x55u8, 0xaa, 0xff, 0x0f, 0xf0, 0x77] {
        // canonical encodings with this pattern, top byte limited so the
        // value stays below r (the top byte of r is 0x73)
        let mut b = [byte; 32];
        b[31] &= 0x73;
        if let Some(x) = Option::<Scalar>::from(Scalar::from_bytes(&b)) {
            v.push(x);
        }
        v.push(Scalar::from_bytes_wide(&[byte; 64]));
    }
    // every top-window digit that a canonical scalar can have
    for top in 0..8u8 {
        let mut b = [0xffu8; 32];
        b[31] = (top << 4) | 0x0f;
        if let Some(x) = Option::<Scalar>::from(Scalar::from_bytes(&b)) {
            v.push(x);
        }
        let mut b = [0u8; 32];
        b[31] = top << 4;
        v.push(Option::<Scalar>::from(Scalar::from_bytes(&b)).unwrap());
    }
    v
}

#[test]
fn msm_single_term_equals_multiplication_for_adversarial_scalars() {
    let points = [
        G1Projective::generator(),
        -G1Projective::generator(),
        G1Projective::generator() * Scalar::from(0x1234_5678u64),
        G1Projective::identity(),
        torsion_point(),
    ];
    for s in adversarial_scalars() {
        for p in &points {
            assert_eq!(msm_vartime(&[*p], &[s]), p * s);
        }
    }
}

#[test]
fn msm_equals_naive_sum() {
    let g = G1Projective::generator();
    let rnd = scalars(64, 21);
    let adv = adversarial_scalars();
    // random sizes, random points and scalars
    for n in 0..=20usize {
        let pts: Vec<G1Projective> = (0..n).map(|i| g * rnd[i] + g).collect();
        let sc: Vec<Scalar> = (0..n).map(|i| rnd[(i * 7 + n) % 64]).collect();
        assert_eq!(msm_vartime(&pts, &sc), naive_msm(&pts, &sc));
        // the same points with adversarial scalars
        let sc: Vec<Scalar> = (0..n).map(|i| adv[(i * 37 + n * 11) % adv.len()]).collect();
        assert_eq!(msm_vartime(&pts, &sc), naive_msm(&pts, &sc));
    }
    let h1 = g * rnd[0];
    let h2 = g * rnd[1];
    let cases: Vec<(Vec<G1Projective>, Vec<Scalar>)> = vec![
        // empty and all-zero sums
        (vec![], vec![]),
        (vec![h1, h2], vec![Scalar::zero(), Scalar::zero()]),
        // repeated, opposite and identity points
        (vec![h1, h1, h1], vec![rnd[2], rnd[3], rnd[4]]),
        (vec![h1, -h1], vec![rnd[5], rnd[5]]),
        (vec![h1, -h1], vec![rnd[5], rnd[6]]),
        (vec![h1, h1], vec![rnd[7], -rnd[7]]),
        (
            vec![h1, G1Projective::identity(), h2],
            vec![rnd[8], rnd[9], rnd[10]],
        ),
        // a "proof point" equal to a sum of generators, next to them
        (vec![h1 + h2, h1, h2], vec![rnd[11], -rnd[11], -rnd[11]]),
        (vec![h1 + h2, h1, h2], vec![rnd[12], rnd[13], rnd[14]]),
        // points whose tables overlap the accumulator: P and 16P, 256P
        (
            vec![h1, h1 * Scalar::from(16u64), h1 * Scalar::from(256u64)],
            vec![Scalar::from(16u64), -Scalar::one(), Scalar::one()],
        ),
        (
            vec![h1, h1 * Scalar::from(16u64)],
            vec![-Scalar::from(16u64), Scalar::one()],
        ),
        // P1-like and generator coincidences
        (
            vec![g, g, -g],
            vec![-Scalar::one(), -Scalar::one(), Scalar::from(2u64)],
        ),
        // a point outside G1 (on the curve): the group law still holds
        (vec![torsion_point(), h1], vec![rnd[15], rnd[16]]),
        (
            vec![torsion_point(), torsion_point()],
            vec![Scalar::one(), Scalar::from(2u64)],
        ),
    ];
    for (pts, sc) in cases {
        assert_eq!(msm_vartime(&pts, &sc), naive_msm(&pts, &sc));
    }
    // every adversarial scalar in a two-term sum with a random partner
    for (i, s) in adv.iter().enumerate() {
        let pts = [h1, h2];
        let sc = [*s, rnd[i % 64]];
        assert_eq!(msm_vartime(&pts, &sc), naive_msm(&pts, &sc));
    }
}

#[test]
#[should_panic(expected = "length mismatch")]
fn msm_rejects_length_mismatch() {
    let g = G1Projective::generator();
    msm_vartime(&[g, g], &[Scalar::one()]);
}

#[test]
fn msm_over_generators_equals_dot() {
    for suite in SUITES {
        let gens = create_generators(suite, 12, &suite.api_id()).unwrap();
        let s: Vec<Scalar> = scalars(12, 3);
        let si: Vec<ScalarInput> = s.iter().copied().map(Into::into).collect();
        assert_eq!(msm_vartime(&gens, &s), dot(&gens, &si).unwrap());
        assert_eq!(dot(&gens[..2], &si[..1]), Err(INVALID));
    }
}

#[test]
fn cached_generator_fast_path_agrees_with_full_check() {
    for suite in SUITES {
        let api = suite.api_id();
        for count in [1u128, 2, 11, 40] {
            let gens = create_generators(suite, count, &api).unwrap();
            let L = count - 1;
            // the cached list passes both
            assert!(valid_generators(suite, &gens, L));
            assert!(valid_generators_cached(suite, &gens, L, &api));
            // modified lists take the full check and fail it
            let mut torsion = gens.clone();
            torsion[0] = torsion_point();
            assert!(!valid_generators(suite, &torsion, L));
            assert!(!valid_generators_cached(suite, &torsion, L, &api));
            let mut p1 = gens.clone();
            p1[0] = suite.P1();
            assert!(!valid_generators_cached(suite, &p1, L, &api));
            let mut ident = gens.clone();
            ident[0] = G1Projective::identity();
            assert!(!valid_generators_cached(suite, &ident, L, &api));
            if count >= 2 {
                let mut dup = gens.clone();
                dup[1] = dup[0];
                assert!(!valid_generators_cached(suite, &dup, L, &api));
            }
            // wrong length
            assert!(!valid_generators_cached(suite, &gens, L + 1, &api));
            // a valid list that is not the cached one: full check, same answer
            let other: Vec<G1Projective> = gens.iter().map(|g| g.double()).collect();
            assert_eq!(
                valid_generators_cached(suite, &other, L, &api),
                valid_generators(suite, &other, L)
            );
            // the cached list under another api_id is not trusted blindly
            assert_eq!(
                valid_generators_cached(suite, &gens, L, b"OTHER-API"),
                valid_generators(suite, &gens, L)
            );
        }
    }
}

#[test]
fn in_g1_variants_agree_on_valid_inputs() {
    for suite in SUITES {
        let api = suite.api_id();
        let gens = create_generators(suite, 6, &api).unwrap();
        let PK = SkToPk(41u64.into()).unwrap();
        assert_eq!(
            calculate_domain(suite, &PK, &gens[0], &gens[1..], b"hdr", &api).unwrap(),
            calculate_domain_in_g1(suite, &PK, &gens[0], &gens[1..], b"hdr", &api).unwrap()
        );
        assert_eq!(
            presentation_context(b"ph", &gens[..3]).unwrap(),
            presentation_context_in_g1(b"ph", &gens[..3]).unwrap()
        );
        let proof = Proof {
            A_bar: gens[0],
            B_bar: gens[1],
            D: gens[2],
            e_hat: 1u64.into(),
            r1_hat: 2u64.into(),
            r3_hat: 3u64.into(),
            m_hats: vec![4u64.into(), 5u64.into()],
            N: 1,
            commitments: vec![gens[3]],
            s_hats: vec![6u64.into()],
            challenge: 7u64.into(),
        };
        assert!(valid_proof_tuple(&proof) && valid_proof_tuple_in_g1(&proof));
        assert_eq!(
            proof_to_octets(&proof).unwrap(),
            proof_to_octets_in_g1(&proof).unwrap()
        );
        let mut zero = proof.clone();
        zero.e_hat = 0u64.into();
        assert!(!valid_proof_tuple_in_g1(&zero));
        let mut ident = proof.clone();
        ident.D = G1Projective::identity();
        assert!(!valid_proof_tuple_in_g1(&ident));
    }
}

#[test]
fn public_entry_points_still_reject_points_outside_g1() {
    let t = torsion_point();
    for suite in SUITES {
        let api = suite.api_id();
        let gens = create_generators(suite, 4, &api).unwrap();
        let PK = SkToPk(41u64.into()).unwrap();
        // public helpers keep their checks
        assert_eq!(
            calculate_domain(suite, &PK, &t, &gens[1..], b"", &api),
            Err(INVALID)
        );
        assert_eq!(
            calculate_domain(suite, &PK, &gens[0], &[t], b"", &api),
            Err(INVALID)
        );
        assert_eq!(presentation_context(b"", &[t]), Err(INVALID));
        assert!(!in_g1(&[t]));
        let proof = Proof {
            A_bar: gens[0],
            B_bar: gens[1],
            D: t,
            e_hat: 1u64.into(),
            r1_hat: 2u64.into(),
            r3_hat: 3u64.into(),
            m_hats: vec![4u64.into()],
            N: 0,
            commitments: vec![],
            s_hats: vec![],
            challenge: 7u64.into(),
        };
        assert!(!valid_proof_tuple(&proof));
        assert_eq!(proof_to_octets(&proof), Err(INVALID));

        // a real signature and proof
        let messages: Vec<ScalarInput> = [7u64, 11, 13].into_iter().map(Into::into).collect();
        let sig = CoreSign(suite, 41u64.into(), &PK, &gens, b"hdr", &messages, &api).unwrap();
        CoreVerify(suite, &PK, &sig, &gens, b"hdr", &messages, &api).unwrap();
        let mut bad_gens = gens.clone();
        bad_gens[2] = t;
        // generators outside G1 are rejected by every core operation
        assert_eq!(
            CoreSign(suite, 41u64.into(), &PK, &bad_gens, b"hdr", &messages, &api),
            Err(INVALID)
        );
        assert_eq!(
            CoreVerify(suite, &PK, &sig, &bad_gens, b"hdr", &messages, &api),
            Err(INVALID)
        );
        let disclosed: Vec<Index> = vec![2u64.into()];
        let committed: Vec<Index> = vec![0u64.into()];
        let mut rng = OsRandom;
        assert!(
            CoreProofGen(
                suite, &PK, &sig, &bad_gens, b"hdr", b"ph", &messages, &disclosed, &committed,
                None, &api, &mut rng,
            )
            .is_err()
        );
        let (proof, (_, rands)) = CoreProofGen(
            suite, &PK, &sig, &gens, b"hdr", b"ph", &messages, &disclosed, &committed, None, &api,
            &mut rng,
        )
        .unwrap();
        let decoded = octets_to_proof(&proof).unwrap();
        let (Y_0, Y_1) = commitment_generators(suite, &api).unwrap();
        assert_eq!(
            decoded.commitments,
            vec![Y_0 * messages[0].to_scalar().unwrap() + Y_1 * rands[0].to_scalar().unwrap()]
        );
        let verify = |g: &[G1Projective], c: &[G1Projective]| {
            CoreProofVerify(
                suite,
                &PK,
                &proof,
                g,
                b"hdr",
                b"ph",
                &messages[2..],
                &disclosed,
                &committed,
                c,
                &api,
            )
        };
        verify(&gens, &decoded.commitments).unwrap();
        assert_eq!(verify(&bad_gens, &decoded.commitments), Err(INVALID));
        // caller-supplied commitments outside G1 (or merely different) are rejected
        assert_eq!(verify(&gens, &[t]), Err(INVALID));
        assert_eq!(verify(&gens, &[decoded.commitments[0] + t]), Err(INVALID));
        // a proof whose commitment encodes a point outside G1 fails to decode
        let mut bytes = proof.clone();
        // N (8) | A_bar, B_bar, D | e_hat, r1_hat, r3_hat, m_hats | commitments ...
        let off = 8 + 3 * 48 + (3 + decoded.m_hats.len()) * 32;
        assert_eq!(
            bytes[off..off + 48],
            crate::primitives::point_to_octets_E1(&decoded.commitments[0])
        );
        let mut enc = [0u8; 48];
        enc[0] = 0x80;
        bytes[off..off + 48].copy_from_slice(&enc);
        assert_eq!(octets_to_proof(&bytes), Err(INVALID));
    }
}

/// O5: one combined Miller loop and one final exponentiation give the same
/// verdict as the product of individual pairings, identities included.
#[test]
fn combined_pairing_equals_product_of_pairings() {
    use crate::core::pairing_product_is_identity;
    use crate::params::BP2;
    use bls12_381::{G2Affine, G2Projective, Gt, pairing};
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();
    let reference = |terms: &[(G1Projective, G2Projective)]| {
        terms.iter().fold(Gt::identity(), |acc, (p, q)| {
            acc + pairing(&G1Affine::from(p), &G2Affine::from(q))
        }) == Gt::identity()
    };
    let s = scalars(6, 11);
    let cases: Vec<Vec<(G1Projective, G2Projective)>> = vec![
        // e(aP, Q) * e(-aP, Q) = 1
        vec![(g1 * s[0], g2), (-(g1 * s[0]), g2)],
        // BBS shape: e(A, W) * e(-SK*A, BP2) = 1 with W = SK*BP2
        vec![(g1 * s[1], BP2() * s[2]), (-(g1 * (s[1] * s[2])), BP2())],
        // not the identity
        vec![(g1 * s[1], BP2() * s[2]), (-(g1 * (s[1] * s[3])), BP2())],
        vec![(g1, g2), (g1, g2)],
        // identity terms contribute 1
        vec![
            (G1Projective::identity(), g2),
            (g1 * s[4], G2Projective::identity()),
        ],
        vec![(G1Projective::identity(), g2), (g1, g2)],
        vec![],
    ];
    for terms in cases {
        assert_eq!(pairing_product_is_identity(&terms), reference(&terms));
    }
}

/// O4a: ProofInit with B reused from the signature check equals ProofInit,
/// and a B computed for another domain is not used.
#[test]
fn proof_init_reuses_base_only_for_the_same_domain() {
    use crate::core::{ProofInit, proof_init_with_base};
    use crate::utils::octets_to_signature;
    for suite in SUITES {
        let api = suite.api_id();
        let gens = create_generators(suite, 4, &api).unwrap();
        let PK = SkToPk(41u64.into()).unwrap();
        let messages: Vec<ScalarInput> = [7u64, 11, 13].into_iter().map(Into::into).collect();
        let sig = CoreSign(suite, 41u64.into(), &PK, &gens, b"hdr", &messages, &api).unwrap();
        let sig = octets_to_signature(&sig).unwrap();
        let random: Vec<ScalarInput> = (2u64..9).map(Into::into).collect();
        let undisclosed: Vec<Index> = vec![0u64.into(), 1u64.into()];
        let committed: Vec<Index> = vec![1u64.into()];
        let s_tildes: Vec<ScalarInput> = vec![17u64.into()];
        let domain = calculate_domain(suite, &PK, &gens[0], &gens[1..], b"hdr", &api).unwrap();
        let B = suite.P1()
            + gens[0] * domain.to_scalar().unwrap()
            + dot(&gens[1..], &messages).unwrap();
        let run = |base: Option<&(ScalarInput, G1Projective)>| {
            proof_init_with_base(
                suite,
                &PK,
                &sig,
                &gens,
                &random,
                b"hdr",
                &messages,
                &undisclosed,
                &committed,
                &s_tildes,
                &api,
                base,
            )
            .unwrap()
        };
        let reference = ProofInit(
            suite,
            &PK,
            &sig,
            &gens,
            &random,
            b"hdr",
            &messages,
            &undisclosed,
            &committed,
            &s_tildes,
            &api,
        )
        .unwrap();
        let same = |x: &crate::types::InitResult| {
            x.A_bar == reference.A_bar
                && x.B_bar == reference.B_bar
                && x.D == reference.D
                && x.T1 == reference.T1
                && x.T2 == reference.T2
                && x.domain == reference.domain
                && x.C_tildes == reference.C_tildes
        };
        assert!(same(&run(None)));
        assert!(same(&run(Some(&(domain, B)))));
        // a base computed for a different domain is ignored
        let other_domain: ScalarInput = (domain.to_scalar().unwrap() + Scalar::one()).into();
        assert!(same(&run(Some(&(other_domain, G1Projective::generator())))));
    }
}

/// The mandatory signature check still runs inside proof generation.
#[test]
fn proof_generation_still_rejects_an_invalid_signature() {
    for suite in SUITES {
        let api = suite.api_id();
        let gens = create_generators(suite, 4, &api).unwrap();
        let PK = SkToPk(41u64.into()).unwrap();
        let messages: Vec<ScalarInput> = [7u64, 11, 13].into_iter().map(Into::into).collect();
        let sig = CoreSign(suite, 41u64.into(), &PK, &gens, b"hdr", &messages, &api).unwrap();
        let generate = |sig: &[u8], msgs: &[ScalarInput]| {
            CoreProofGen(
                suite,
                &PK,
                sig,
                &gens,
                b"hdr",
                b"ph",
                msgs,
                &[2u64.into()],
                &[0u64.into()],
                None,
                &api,
                &mut OsRandom,
            )
        };
        assert!(generate(&sig, &messages).is_ok());
        // another message vector than the one signed
        let mut other = messages.clone();
        other[1] = 12u64.into();
        assert_eq!(generate(&sig, &other).map(|_| ()), Err(INVALID));
        // another e (still a valid encoding)
        let mut bad = sig.clone();
        bad[79] ^= 1;
        assert_eq!(generate(&bad, &messages).map(|_| ()), Err(INVALID));
        // a signature by another key
        let PK2 = SkToPk(43u64.into()).unwrap();
        let sig2 = CoreSign(suite, 43u64.into(), &PK2, &gens, b"hdr", &messages, &api).unwrap();
        assert_eq!(generate(&sig2, &messages).map(|_| ()), Err(INVALID));
    }
}

/// The verifier's reconstruction (T1, T2, C~) with the multi-scalar
/// multiplication equals the textbook formulas, for honest proofs and for
/// proofs whose points and scalars a malicious holder chose to collide with
/// generators, cancel, or stress the window decomposition.
#[test]
fn verifier_reconstruction_equals_textbook_formulas_on_adversarial_proofs() {
    use crate::proof_protocol::ProofVerifyInit;
    use crate::utils::calculate_domain;
    for suite in SUITES {
        let api = suite.api_id();
        let gens = create_generators(suite, 6, &api).unwrap();
        let PK = SkToPk(41u64.into()).unwrap();
        let messages: Vec<ScalarInput> =
            [7u64, 11, 13, 17, 19].into_iter().map(Into::into).collect();
        let sig = CoreSign(suite, 41u64.into(), &PK, &gens, b"hdr", &messages, &api).unwrap();
        let disclosed: Vec<Index> = vec![1u64.into(), 3u64.into()];
        let committed: Vec<Index> = vec![0u64.into(), 4u64.into()];
        let disclosed_msgs = vec![messages[1], messages[3]];
        let (bytes, _) = CoreProofGen(
            suite,
            &PK,
            &sig,
            &gens,
            b"hdr",
            b"ph",
            &messages,
            &disclosed,
            &committed,
            None,
            &api,
            &mut OsRandom,
        )
        .unwrap();
        let honest = octets_to_proof(&bytes).unwrap();
        let domain = calculate_domain(suite, &PK, &gens[0], &gens[1..], b"hdr", &api).unwrap();
        let (Y_0, Y_1) = commitment_generators(suite, &api).unwrap();
        let textbook = |p: &Proof| {
            let c = p.challenge.to_scalar().unwrap();
            let sc = |x: &ScalarInput| x.to_scalar().unwrap();
            let T1 = p.B_bar * c + p.A_bar * sc(&p.e_hat) + p.D * sc(&p.r1_hat);
            let Bv = suite.P1()
                + gens[0] * domain.to_scalar().unwrap()
                + gens[2] * sc(&disclosed_msgs[0])
                + gens[4] * sc(&disclosed_msgs[1]);
            let T2 = Bv * c
                + p.D * sc(&p.r3_hat)
                + gens[1] * sc(&p.m_hats[0])
                + gens[3] * sc(&p.m_hats[1])
                + gens[5] * sc(&p.m_hats[2]);
            // committed indexes 0 and 4 are undisclosed positions 0 and 2
            let C = [
                Y_0 * sc(&p.m_hats[0]) + Y_1 * sc(&p.s_hats[0]) - p.commitments[0] * c,
                Y_0 * sc(&p.m_hats[2]) + Y_1 * sc(&p.s_hats[1]) - p.commitments[1] * c,
            ];
            (T1, T2, C)
        };
        let adv = adversarial_scalars();
        let pick = |i: usize| -> ScalarInput {
            let x = adv[i % adv.len()];
            if x == Scalar::zero() {
                Scalar::one().into()
            } else {
                x.into()
            }
        };
        let mut proofs = vec![honest.clone()];
        for round in 0..40usize {
            let mut p = honest.clone();
            match round % 5 {
                0 => p.D = gens[1 + round % 5],
                1 => p.D = -suite.P1(),
                2 => p.A_bar = p.B_bar,
                3 => p.commitments[0] = Y_0,
                _ => p.D = gens[0] + gens[1],
            }
            p.e_hat = pick(round * 3);
            p.r1_hat = pick(round * 5 + 1);
            p.r3_hat = pick(round * 7 + 2);
            p.m_hats = vec![
                pick(round * 11 + 3),
                pick(round * 13 + 4),
                pick(round * 17 + 5),
            ];
            p.s_hats = vec![pick(round * 19 + 6), pick(round * 23 + 7)];
            p.challenge = pick(round * 29 + 8);
            proofs.push(p);
        }
        for p in &proofs {
            let init = ProofVerifyInit(
                suite,
                &PK,
                p,
                &gens,
                b"hdr",
                &disclosed_msgs,
                &disclosed,
                &committed,
                &api,
            )
            .unwrap();
            let (T1, T2, C) = textbook(p);
            assert_eq!(init.T1, T1);
            assert_eq!(init.T2, T2);
            assert_eq!(init.C_tildes, C.to_vec());
        }
    }
}
