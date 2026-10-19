//! Spec 3.7.2–3.7.4: internal proof responses and transcript reconstruction.

use bls12_381::{G1Projective, Scalar};

use crate::helpers::{
    complement, disjoint, in_g1, msm_vartime, nonidentity, nonzero_scalar, position, select,
    valid_generators_cached, valid_indexes, valid_message_vector, valid_scalars,
};
use crate::params::{Ciphersuite, MAX_MESSAGES};
use crate::types::{Index, InitResult, Proof, ScalarInput};
use crate::utils::{
    Field, calculate_domain_in_g1, commitment_generators, hash_to_scalar,
    presentation_context_in_g1, proof_to_octets_in_g1, serialize_in_g1, valid_proof_tuple_in_g1,
};
use crate::{BbsError, BbsResult, INVALID};

/// Spec 3.7.2 ProofFinalize. Responses use the masks from the same ProofInit.
#[allow(clippy::too_many_arguments)]
pub(crate) fn ProofFinalize(
    _suite: Ciphersuite,
    init_res: &InitResult,
    challenge: ScalarInput,
    e_value: ScalarInput,
    random_scalars: &[ScalarInput],
    undisclosed_messages: &[ScalarInput],
    commitments: &[G1Projective],
    commitment_rands: &[ScalarInput],
    s_tildes: &[ScalarInput],
) -> BbsResult<Vec<u8>> {
    let InitResult {
        A_bar,
        B_bar,
        D,
        C_tildes,
        ..
    } = init_res;
    let U = undisclosed_messages.len();
    let N = commitments.len();
    if N > U || !valid_message_vector(undisclosed_messages) {
        return Err(INVALID);
    }
    if random_scalars.len() as u128 != U as u128 + 5
        || commitment_rands.len() != N
        || s_tildes.len() != N
        || C_tildes.len() != N
    {
        return Err(INVALID);
    }
    if !valid_scalars(random_scalars)
        || !valid_scalars(commitment_rands)
        || !valid_scalars(s_tildes)
    {
        return Err(INVALID);
    }
    if !nonzero_scalar(challenge) || !nonzero_scalar(e_value) {
        return Err(INVALID);
    }
    let r1 = random_scalars[0].to_scalar()?;
    let r2 = random_scalars[1].to_scalar()?;
    let e_tilde = random_scalars[2].to_scalar()?;
    let r1_tilde = random_scalars[3].to_scalar()?;
    let r3_tilde = random_scalars[4].to_scalar()?;
    let m_tildes = &random_scalars[5..U + 5];
    if r1 == Scalar::zero() || r2 == Scalar::zero() {
        return Err(INVALID);
    }

    let r3 = Option::<Scalar>::from(r2.invert()).ok_or(INVALID)?;
    let c = challenge.to_scalar()?;
    let e_hat = e_tilde + e_value.to_scalar()? * c;
    let r1_hat = r1_tilde - r1 * c;
    let r3_hat = r3_tilde - r3 * c;
    let mut m_hats = Vec::new();
    for k in 0..U {
        m_hats.push((m_tildes[k].to_scalar()? + undisclosed_messages[k].to_scalar()? * c).into());
    }
    let mut s_hats = Vec::new();
    for b in 0..N {
        s_hats.push((s_tildes[b].to_scalar()? + commitment_rands[b].to_scalar()? * c).into());
    }

    let proof = Proof {
        A_bar: *A_bar,
        B_bar: *B_bar,
        D: *D,
        e_hat: e_hat.into(),
        r1_hat: r1_hat.into(),
        r3_hat: r3_hat.into(),
        m_hats,
        N: N as u128,
        commitments: commitments.to_vec(),
        s_hats,
        challenge,
    };
    // Every point was computed by ProofInit from points in G1.
    proof_to_octets_in_g1(&proof)
}

/// Spec 3.7.3 ProofVerifyInit. Reconstruct the shared message responses.
///
/// `proof` must come from `octets_to_proof`, so its points are in G1; the
/// subgroup checks of `valid_proof_tuple` are not repeated.
#[allow(clippy::too_many_arguments)]
pub(crate) fn ProofVerifyInit(
    suite: Ciphersuite,
    PK: &[u8],
    proof: &Proof,
    generators: &[G1Projective],
    header: &[u8],
    disclosed_messages: &[ScalarInput],
    disclosed_indexes: &[Index],
    commitment_indexes: &[Index],
    api_id: &[u8],
) -> BbsResult<InitResult> {
    if !valid_proof_tuple_in_g1(proof) {
        return Err(INVALID);
    }
    let Proof {
        A_bar,
        B_bar,
        D,
        e_hat,
        r1_hat,
        r3_hat,
        m_hats,
        N,
        commitments,
        s_hats,
        challenge: c,
    } = proof;
    let U = m_hats.len();
    let R = disclosed_indexes.len();
    let L = R as u128 + U as u128;
    if !valid_generators_cached(suite, generators, L, api_id) {
        return Err(INVALID);
    }
    if !valid_indexes(disclosed_indexes, L)
        || !valid_indexes(commitment_indexes, L)
        || !disjoint(disclosed_indexes, commitment_indexes)
    {
        return Err(INVALID);
    }
    if disclosed_messages.len() != R
        || !valid_message_vector(disclosed_messages)
        || commitment_indexes.len() as u128 != *N
    {
        return Err(INVALID);
    }

    // valid_generators fixes L + 1 to the in-memory generators length.
    let L = generators.len() - 1;
    let undisclosed_indexes = complement(disclosed_indexes, L)?;
    let Q_1 = &generators[0];
    let msg_generators = &generators[1..L + 1];
    let domain = calculate_domain_in_g1(suite, PK, Q_1, msg_generators, header, api_id)?;
    let c = c.to_scalar()?;
    // Verifier side: public scalars, variable-time multiplication.
    let T1 = msm_vartime(
        &[*B_bar, *A_bar, *D],
        &[c, e_hat.to_scalar()?, r1_hat.to_scalar()?],
    );
    // T2 = Bv * c + D * r3^ + sum_j H_j * m^_j with
    // Bv = P1 + Q_1 * domain + sum_i H_i * m_i (disclosed), computed as one
    // multi-scalar multiplication with c folded into the Bv scalars:
    // c*P1 + (c*domain)*Q_1 + sum_i (c*m_i)*H_i + r3^*D + sum_j m^_j*H_j.
    // This is the same group element (scalar products mod r).
    let disclosed_generators = select(msg_generators, disclosed_indexes)?;
    let undisclosed_generators = select(msg_generators, &undisclosed_indexes)?;
    if disclosed_generators.len() != disclosed_messages.len()
        || undisclosed_generators.len() != m_hats.len()
    {
        return Err(INVALID);
    }
    let mut t2_points = Vec::with_capacity(L + 3);
    let mut t2_scalars = Vec::with_capacity(L + 3);
    t2_points.push(suite.P1());
    t2_scalars.push(c);
    t2_points.push(*Q_1);
    t2_scalars.push(c * domain.to_scalar()?);
    for (h, m) in disclosed_generators.iter().zip(disclosed_messages) {
        t2_points.push(*h);
        t2_scalars.push(c * m.to_scalar()?);
    }
    t2_points.push(*D);
    t2_scalars.push(r3_hat.to_scalar()?);
    for (h, m) in undisclosed_generators.iter().zip(m_hats) {
        t2_points.push(*h);
        t2_scalars.push(m.to_scalar()?);
    }
    let T2 = msm_vartime(&t2_points, &t2_scalars);

    // SI-003: explicit INVALID propagation approved by Peter on 2026-10-15.
    let (Y_0, Y_1) = commitment_generators(suite, api_id)?;
    let mut C_tildes = Vec::new();
    for b in 0..commitment_indexes.len() {
        let k = position(&undisclosed_indexes, &commitment_indexes[b])?;
        C_tildes.push(msm_vartime(
            &[Y_0, Y_1, commitments[b]],
            &[m_hats[k].to_scalar()?, s_hats[b].to_scalar()?, -c],
        ));
    }
    Ok(InitResult {
        A_bar: *A_bar,
        B_bar: *B_bar,
        D: *D,
        T1,
        T2,
        domain,
        C_tildes,
    })
}

/// Spec 3.7.4 ProofChallengeCalculate. Field definitions determine serialization.
///
/// Callers (`CoreProofGen`, `CoreProofVerify`) pass only points in G1:
/// decoded points, the caller's commitments after they were compared equal
/// to decoded ones, and points computed from those and from validated
/// generators.  The spec's `in_g1` condition therefore holds and is not
/// re-evaluated (it is asserted in debug builds); the identity checks stay.
#[allow(clippy::too_many_arguments)]
pub(crate) fn ProofChallengeCalculate(
    suite: Ciphersuite,
    init_res: &InitResult,
    disclosed_messages: &[ScalarInput],
    disclosed_indexes: &[Index],
    commitments: &[G1Projective],
    commitment_indexes: &[Index],
    ph: &[u8],
    api_id: &[u8],
) -> BbsResult<ScalarInput> {
    let InitResult {
        A_bar,
        B_bar,
        D,
        T1,
        T2,
        domain,
        C_tildes,
    } = init_res;
    let R = disclosed_indexes.len();
    let N = commitment_indexes.len();
    if R as u128 > u64::MAX as u128
        || N as u128 > u64::MAX as u128
        || ph.len() as u128 > u64::MAX as u128
    {
        return Err(BbsError::Abort(
            "proof transcript count or ph length exceeds u64",
        ));
    }
    if disclosed_messages.len() != R || commitments.len() != N || C_tildes.len() != N {
        return Err(INVALID);
    }
    if !valid_indexes(disclosed_indexes, MAX_MESSAGES)
        || !valid_indexes(commitment_indexes, MAX_MESSAGES)
        || !disjoint(disclosed_indexes, commitment_indexes)
    {
        return Err(INVALID);
    }
    let mut scalars = disclosed_messages.to_vec();
    scalars.push(*domain);
    if !valid_scalars(&scalars) {
        return Err(INVALID);
    }
    let mut points = vec![*A_bar, *B_bar, *D, *T1, *T2];
    points.extend_from_slice(commitments);
    points.extend_from_slice(C_tildes);
    let mut nonidentity_points = vec![*A_bar, *B_bar, *D];
    nonidentity_points.extend_from_slice(commitments);
    debug_assert!(in_g1(&points), "ProofChallengeCalculate: point outside G1");
    if !nonidentity(&nonidentity_points) {
        return Err(INVALID);
    }

    let mut c_arr = vec![Field::U64(R as u128)];
    for a in 0..R {
        let Index::Integer(index) = disclosed_indexes[a] else {
            return Err(INVALID);
        };
        c_arr.push(Field::U64(index as u128));
        c_arr.push(Field::Scalar(disclosed_messages[a]));
    }
    c_arr.extend([
        Field::G1(A_bar),
        Field::G1(B_bar),
        Field::G1(D),
        Field::G1(T1),
        Field::G1(T2),
        Field::Scalar(*domain),
        Field::U64(N as u128),
    ]);
    for b in 0..N {
        let Index::Integer(index) = commitment_indexes[b] else {
            return Err(INVALID);
        };
        c_arr.push(Field::U64(index as u128));
        c_arr.push(Field::G1(&commitments[b]));
        c_arr.push(Field::G1(&C_tildes[b]));
    }
    let ctx = presentation_context_in_g1(ph, commitments)?;
    let c_octs = [serialize_in_g1(&c_arr)?, ctx].concat();
    hash_to_scalar(
        suite,
        &c_octs,
        &[api_id, b"COM_DIS_ETSI_PROOF_V1_H2S_"].concat(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{CoreSign, ProofInit};
    use crate::interface::SkToPk;
    use crate::utils::{create_generators, octets_to_proof, octets_to_signature};

    /// Spec 3.7.4: independently assemble transcript bytes, including empty N and ph.
    #[test]
    fn transcript_field_widths_and_identity_policy() {
        use crate::primitives::point_to_octets_E1;
        let point = G1Projective::generator();
        let identity = G1Projective::identity();
        for suite in [Ciphersuite::Sha256, Ciphersuite::Shake256] {
            for N in [0usize, 1] {
                let init = InitResult {
                    A_bar: point,
                    B_bar: point,
                    D: point,
                    T1: identity,
                    T2: identity,
                    domain: 1u64.into(),
                    C_tildes: vec![identity; N],
                };
                let commitments = vec![point; N];
                let indexes: Vec<Index> = (0..N).map(|i| (i as u64).into()).collect();
                let mut bytes = 1u64.to_be_bytes().to_vec(); // R
                bytes.extend_from_slice(&2u64.to_be_bytes()); // disclosed index
                bytes.extend_from_slice(&ScalarInput::from(1).0); // scalar, not u64
                for p in [point, point, point, identity, identity] {
                    bytes.extend_from_slice(&point_to_octets_E1(&p));
                }
                bytes.extend_from_slice(&ScalarInput::from(1).0); // domain
                bytes.extend_from_slice(&(N as u64).to_be_bytes());
                if N == 1 {
                    bytes.extend_from_slice(&0u64.to_be_bytes());
                    bytes.extend_from_slice(&point_to_octets_E1(&point));
                    bytes.extend_from_slice(&point_to_octets_E1(&identity));
                }
                bytes.extend_from_slice(&0u64.to_be_bytes()); // empty ph length
                bytes.extend_from_slice(&(N as u64).to_be_bytes());
                for p in &commitments {
                    bytes.extend_from_slice(&point_to_octets_E1(p));
                }
                let expected = hash_to_scalar(
                    suite,
                    &bytes,
                    &[suite.api_id().as_slice(), b"COM_DIS_ETSI_PROOF_V1_H2S_"].concat(),
                )
                .unwrap();
                assert_eq!(
                    ProofChallengeCalculate(
                        suite,
                        &init,
                        &[1u64.into()],
                        &[2u64.into()],
                        &commitments,
                        &indexes,
                        b"",
                        &suite.api_id()
                    )
                    .unwrap(),
                    expected
                );
                let mut invalid = init.clone();
                invalid.A_bar = identity;
                assert_eq!(
                    ProofChallengeCalculate(
                        suite,
                        &invalid,
                        &[1u64.into()],
                        &[2u64.into()],
                        &commitments,
                        &indexes,
                        b"",
                        &suite.api_id()
                    ),
                    Err(INVALID)
                );
            }
        }
    }

    /// Spec 3.7.2. Check response arithmetic independently of verification.
    #[test]
    fn responses_use_inverse_r2_and_reject_zero_response() {
        let point = G1Projective::generator();
        let init = InitResult {
            A_bar: point,
            B_bar: point,
            D: point,
            T1: point,
            T2: point,
            domain: 1u64.into(),
            C_tildes: vec![point],
        };
        let random: Vec<ScalarInput> = [2u64, 3, 5, 13, 17, 19]
            .into_iter()
            .map(Into::into)
            .collect();
        let encoded = ProofFinalize(
            Ciphersuite::Sha256,
            &init,
            11u64.into(),
            7u64.into(),
            &random,
            &[23u64.into()],
            &[point],
            &[29u64.into()],
            &[31u64.into()],
        )
        .unwrap();
        let proof = octets_to_proof(&encoded).unwrap();
        assert_eq!(proof.e_hat, 82u64.into());
        assert_eq!(proof.r1_hat, (-Scalar::from(9u64)).into());
        let inverse_r2 = Option::<Scalar>::from(Scalar::from(3u64).invert()).unwrap();
        assert_eq!(
            proof.r3_hat,
            (Scalar::from(17u64) - inverse_r2 * Scalar::from(11u64)).into()
        );
        assert_eq!(proof.m_hats, vec![272u64.into()]);
        assert_eq!(proof.s_hats, vec![350u64.into()]);
        let mut zero_response = random.clone();
        zero_response[3] = 22u64.into();
        assert_eq!(
            ProofFinalize(
                Ciphersuite::Sha256,
                &init,
                11u64.into(),
                7u64.into(),
                &zero_response,
                &[23u64.into()],
                &[point],
                &[29u64.into()],
                &[31u64.into()],
            ),
            Err(INVALID)
        );
    }

    /// Spec 3.7.1–3.7.4. Shared responses reconstruct every initialization point.
    #[test]
    fn mixed_transcript_reconstruction_and_binding() {
        for suite in [Ciphersuite::Sha256, Ciphersuite::Shake256] {
            let api = suite.api_id();
            let PK = SkToPk(41u64.into()).unwrap();
            let generators = create_generators(suite, 4, &api).unwrap();
            let messages: Vec<ScalarInput> = [7u64, 11, 13].into_iter().map(Into::into).collect();
            let signature = CoreSign(
                suite,
                41u64.into(),
                &PK,
                &generators,
                b"header",
                &messages,
                &api,
            )
            .unwrap();
            let signature = octets_to_signature(&signature).unwrap();
            let undisclosed = [0u64.into(), 1u64.into()];
            let disclosed = [2u64.into()];
            let committed = [1u64.into()];
            let random: Vec<ScalarInput> = (2u64..9).map(Into::into).collect();
            let s_tildes = [17u64.into()];
            let rands: [ScalarInput; 1] = [19u64.into()];
            let (Y_0, Y_1) = commitment_generators(suite, &api).unwrap();
            let commitments =
                [Y_0 * messages[1].to_scalar().unwrap() + Y_1 * rands[0].to_scalar().unwrap()];
            let init = ProofInit(
                suite,
                &PK,
                &signature,
                &generators,
                &random,
                b"header",
                &messages,
                &undisclosed,
                &committed,
                &s_tildes,
                &api,
            )
            .unwrap();
            let challenge = ProofChallengeCalculate(
                suite,
                &init,
                &messages[2..],
                &disclosed,
                &commitments,
                &committed,
                b"presentation",
                &api,
            )
            .unwrap();
            let bytes = ProofFinalize(
                suite,
                &init,
                challenge,
                signature.e,
                &random,
                &messages[..2],
                &commitments,
                &rands,
                &s_tildes,
            )
            .unwrap();
            let proof = octets_to_proof(&bytes).unwrap();
            let reconstructed = ProofVerifyInit(
                suite,
                &PK,
                &proof,
                &generators,
                b"header",
                &messages[2..],
                &disclosed,
                &committed,
                &api,
            )
            .unwrap();
            assert_eq!(reconstructed.A_bar, init.A_bar);
            assert_eq!(reconstructed.B_bar, init.B_bar);
            assert_eq!(reconstructed.D, init.D);
            assert_eq!(reconstructed.T1, init.T1);
            assert_eq!(reconstructed.T2, init.T2);
            assert_eq!(reconstructed.domain, init.domain);
            assert_eq!(reconstructed.C_tildes, init.C_tildes);
            assert_eq!(
                ProofChallengeCalculate(
                    suite,
                    &reconstructed,
                    &messages[2..],
                    &disclosed,
                    &commitments,
                    &committed,
                    b"presentation",
                    &api
                )
                .unwrap(),
                challenge
            );
            assert_ne!(
                ProofChallengeCalculate(
                    suite,
                    &reconstructed,
                    &messages[2..],
                    &disclosed,
                    &commitments,
                    &committed,
                    b"changed",
                    &api
                )
                .unwrap(),
                challenge
            );
            assert!(matches!(
                ProofChallengeCalculate(
                    suite,
                    &reconstructed,
                    &messages[2..],
                    &disclosed,
                    &commitments,
                    &committed,
                    b"presentation",
                    &[0; 256]
                ),
                Err(BbsError::Abort(_))
            ));
            assert!(matches!(
                ProofVerifyInit(
                    suite,
                    &PK,
                    &proof,
                    &generators,
                    b"header",
                    &messages[2..],
                    &disclosed,
                    &disclosed,
                    &api
                ),
                Err(BbsError::Invalid)
            ));
        }
    }
}
