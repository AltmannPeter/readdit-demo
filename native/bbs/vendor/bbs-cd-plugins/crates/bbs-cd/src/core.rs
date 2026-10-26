//! Spec 3.6–3.7: BBS core operations and internal proof initialization.

use crate::helpers::{
    dot, msm_vartime, mul_vartime, select, subset, valid_generators_cached, valid_indexes,
    valid_message_vector, valid_scalars,
};
use crate::params::{BP2, Ciphersuite};
use crate::primitives::octets_to_pubkey;
use crate::types::{Index, InitResult, Proof, ScalarInput, Signature};
use crate::utils::{
    Field, calculate_domain_in_g1, commitment_generators, hash_to_scalar, octets_to_signature,
    serialize, signature_to_octets,
};
use crate::{BbsError, BbsResult, INVALID};
use bls12_381::{
    G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar, multi_miller_loop,
};

/// Whether the product of the pairings e(P_i, Q_i) is the identity of GT.
///
/// Computes one combined Miller loop and a single final exponentiation.
/// The final exponentiation is a group homomorphism, so the result equals
/// the product of the individual pairings for every input; terms with an
/// identity point contribute 1, as in the crate's `pairing`.
pub(crate) fn pairing_product_is_identity(terms: &[(G1Projective, G2Projective)]) -> bool {
    let g1: Vec<G1Affine> = terms.iter().map(|(p, _)| G1Affine::from(p)).collect();
    let g2: Vec<G2Prepared> = terms
        .iter()
        .map(|(_, q)| G2Prepared::from(G2Affine::from(q)))
        .collect();
    let pairs: Vec<(&G1Affine, &G2Prepared)> = g1.iter().zip(g2.iter()).collect();
    multi_miller_loop(&pairs).final_exponentiation() == Gt::identity()
}

/// Spec 3.6.1 CoreSign. Arguments preserve the spec order after the suite.
#[allow(clippy::too_many_arguments)]
pub fn CoreSign(
    suite: Ciphersuite,
    SK: ScalarInput,
    PK: &[u8],
    generators: &[G1Projective],
    header: &[u8],
    messages: &[ScalarInput],
    api_id: &[u8],
) -> BbsResult<Vec<u8>> {
    if !crate::helpers::nonzero_scalar(SK) {
        return Err(INVALID);
    }
    let SK = SK.to_scalar()?;
    let W = octets_to_pubkey(PK)?;
    if W != BP2() * SK {
        return Err(INVALID);
    }
    let L = messages.len();
    if !valid_message_vector(messages)
        || !valid_generators_cached(suite, generators, L as u128, api_id)
    {
        return Err(INVALID);
    }

    let Q_1 = &generators[0];
    let msg_generators = &generators[1..L + 1];
    // The generators passed valid_generators above; no second subgroup check.
    let domain = calculate_domain_in_g1(suite, PK, Q_1, msg_generators, header, api_id)?;
    // Issuer side: the multiplications below stay constant-time.
    let mut e_arr = vec![Field::Scalar(SK.into())];
    e_arr.extend(messages.iter().copied().map(Field::Scalar));
    e_arr.push(Field::Scalar(domain));
    let e = hash_to_scalar(suite, &serialize(&e_arr)?, &[api_id, b"H2S_"].concat())?.to_scalar()?;
    if e == Scalar::zero() || SK + e == Scalar::zero() {
        return Err(INVALID);
    }
    let B = suite.P1() + Q_1 * domain.to_scalar()? + dot(msg_generators, messages)?;
    if bool::from(B.is_identity()) {
        return Err(INVALID);
    }
    let inverse = Option::<Scalar>::from((SK + e).invert()).ok_or(INVALID)?;
    let A = B * inverse;
    signature_to_octets(&Signature { A, e: e.into() })
}

/// Spec 3.6.2 CoreVerify. Ok(()) is VALID; errors preserve INVALID vs ABORT.
pub fn CoreVerify(
    suite: Ciphersuite,
    PK: &[u8],
    signature: &[u8],
    generators: &[G1Projective],
    header: &[u8],
    messages: &[ScalarInput],
    api_id: &[u8],
) -> BbsResult<()> {
    let signature_result = octets_to_signature(signature)?;
    let W = octets_to_pubkey(PK)?;
    core_verify_decoded(
        suite,
        PK,
        &W,
        &signature_result,
        generators,
        header,
        messages,
        api_id,
    )
    .map(|_| ())
}

/// Q_1 * domain + sum_i H_i * m_i (B without P1), as one multi-scalar
/// multiplication.  Holder and verifier side only (variable-time).
fn base_msm(
    Q_1: &G1Projective,
    H: &[G1Projective],
    domain: &ScalarInput,
    messages: &[ScalarInput],
) -> BbsResult<G1Projective> {
    let mut points = Vec::with_capacity(H.len() + 1);
    points.push(*Q_1);
    points.extend_from_slice(H);
    let mut scalars = Vec::with_capacity(messages.len() + 1);
    scalars.push(domain.to_scalar()?);
    for m in messages {
        scalars.push(m.to_scalar()?);
    }
    if points.len() != scalars.len() {
        return Err(INVALID);
    }
    Ok(msm_vartime(&points, &scalars))
}

/// The domain and B computed by a successful `core_verify_decoded`, for
/// reuse by `ProofInit` in the same `CoreProofGen` call.
pub(crate) type VerifiedBase = (ScalarInput, G1Projective);

/// `CoreVerify` after decoding: `W` from `octets_to_pubkey(PK)` and
/// `signature` from `octets_to_signature`, both with their full checks.
/// Lets `CoreProofGen` decode the signature and key once, and returns the
/// domain and B so that `ProofInit` need not recompute B.
#[allow(clippy::too_many_arguments)]
pub(crate) fn core_verify_decoded(
    suite: Ciphersuite,
    PK: &[u8],
    W: &G2Projective,
    signature: &Signature,
    generators: &[G1Projective],
    header: &[u8],
    messages: &[ScalarInput],
    api_id: &[u8],
) -> BbsResult<VerifiedBase> {
    let Signature { A, e } = signature;
    let L = messages.len();
    if !valid_message_vector(messages)
        || !valid_generators_cached(suite, generators, L as u128, api_id)
    {
        return Err(INVALID);
    }

    let Q_1 = &generators[0];
    let msg_generators = &generators[1..L + 1];
    let domain = calculate_domain_in_g1(suite, PK, Q_1, msg_generators, header, api_id)?;
    let B = suite.P1() + base_msm(Q_1, msg_generators, &domain, messages)?;
    // h(A, W) * h(e * A - B, BP2) == 1, as one combined pairing product.
    let lhs = mul_vartime(A, &e.to_scalar()?) - B;
    if !pairing_product_is_identity(&[(*A, *W), (lhs, BP2())]) {
        return Err(INVALID);
    }
    Ok((domain, B))
}

/// Spec 3.7.1 ProofInit. Internal: signature and invocation state are not public API.
///
/// Callers decode the signature and enforce Section 3.6 at their boundary. The
/// direct entry used by unit cross-checks is not exported from the crate.
// Kept with the spec's signature for the unit cross-checks; CoreProofGen
// calls proof_init_with_base.
#[cfg_attr(not(test), allow(dead_code))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn ProofInit(
    suite: Ciphersuite,
    PK: &[u8],
    signature: &Signature,
    generators: &[G1Projective],
    random_scalars: &[ScalarInput],
    header: &[u8],
    messages: &[ScalarInput],
    undisclosed_indexes: &[Index],
    commitment_indexes: &[Index],
    s_tildes: &[ScalarInput],
    api_id: &[u8],
) -> BbsResult<InitResult> {
    proof_init_with_base(
        suite,
        PK,
        signature,
        generators,
        random_scalars,
        header,
        messages,
        undisclosed_indexes,
        commitment_indexes,
        s_tildes,
        api_id,
        None,
    )
}

/// `ProofInit`, optionally reusing B from the mandatory signature check of
/// the same `CoreProofGen` call (same PK, generators, header, messages and
/// api_id).  The domain is still computed here as the spec requires; B is
/// reused only if that domain equals the one B was computed with, so the
/// result is exactly ProofInit's in every case.
#[allow(clippy::too_many_arguments)]
pub(crate) fn proof_init_with_base(
    suite: Ciphersuite,
    PK: &[u8],
    signature: &Signature,
    generators: &[G1Projective],
    random_scalars: &[ScalarInput],
    header: &[u8],
    messages: &[ScalarInput],
    undisclosed_indexes: &[Index],
    commitment_indexes: &[Index],
    s_tildes: &[ScalarInput],
    api_id: &[u8],
    verified: Option<&VerifiedBase>,
) -> BbsResult<InitResult> {
    let Signature { A, e } = signature;
    if bool::from(A.is_identity()) || !crate::helpers::nonzero_scalar(*e) {
        return Err(INVALID);
    }
    let L = messages.len();
    let U = undisclosed_indexes.len();
    let N = commitment_indexes.len();
    if !valid_message_vector(messages)
        || !valid_generators_cached(suite, generators, L as u128, api_id)
    {
        return Err(INVALID);
    }
    if !valid_indexes(undisclosed_indexes, L as u128) {
        return Err(BbsError::Abort("ProofInit invalid undisclosed_indexes"));
    }
    if !valid_indexes(commitment_indexes, L as u128)
        || !subset(commitment_indexes, undisclosed_indexes)
    {
        return Err(INVALID);
    }
    if random_scalars.len() as u128 != U as u128 + 5
        || s_tildes.len() != N
        || !valid_scalars(random_scalars)
        || !valid_scalars(s_tildes)
    {
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

    let Q_1 = &generators[0];
    let msg_generators = &generators[1..L + 1];
    let domain = calculate_domain_in_g1(suite, PK, Q_1, msg_generators, header, api_id)?;
    // Holder side: variable-time multiplication (see helpers::mul_vartime).
    let B = match verified {
        Some((verified_domain, B)) if *verified_domain == domain => *B,
        _ => suite.P1() + base_msm(Q_1, msg_generators, &domain, messages)?,
    };
    let D = mul_vartime(&B, &r2);
    let A_bar = mul_vartime(A, &(r1 * r2));
    let B_bar = msm_vartime(&[D, A_bar], &[r1, -e.to_scalar()?]);
    if bool::from(A_bar.is_identity())
        || bool::from(B_bar.is_identity())
        || bool::from(D.is_identity())
    {
        return Err(INVALID);
    }
    let T1 = msm_vartime(&[A_bar, D], &[e_tilde, r1_tilde]);
    // T2 = D * r3~ + sum_k H_k * m~_k, as one multi-scalar multiplication.
    let mut t2_points = vec![D];
    t2_points.extend(select(msg_generators, undisclosed_indexes)?);
    let mut t2_scalars = vec![r3_tilde];
    for m in m_tildes {
        t2_scalars.push(m.to_scalar()?);
    }
    let T2 = msm_vartime(&t2_points, &t2_scalars);

    // SI-003: explicit INVALID propagation approved by Peter on 2026-10-15.
    let (Y_0, Y_1) = commitment_generators(suite, api_id)?;
    let mut C_tildes = Vec::new();
    for b in 0..N {
        let k = undisclosed_indexes
            .iter()
            .position(|i| i == &commitment_indexes[b])
            .ok_or(INVALID)?;
        C_tildes.push(msm_vartime(
            &[Y_0, Y_1],
            &[m_tildes[k].to_scalar()?, s_tildes[b].to_scalar()?],
        ));
    }
    Ok(InitResult {
        A_bar,
        B_bar,
        D,
        T1,
        T2,
        domain,
        C_tildes,
    })
}

/// Spec 3.6.3 CoreProofGen. Each invocation draws fresh masks from the supplied source.
#[allow(clippy::too_many_arguments)]
pub fn CoreProofGen(
    suite: Ciphersuite,
    PK: &[u8],
    signature: &[u8],
    generators: &[G1Projective],
    header: &[u8],
    ph: &[u8],
    messages: &[ScalarInput],
    disclosed_indexes: &[Index],
    commitment_indexes: &[Index],
    precomputed_rands: Option<&[ScalarInput]>,
    api_id: &[u8],
    rng: &mut dyn crate::types::ScalarSource,
) -> BbsResult<crate::types::ProofOutput> {
    use crate::helpers::{complement, disjoint};
    use crate::proof_protocol::{ProofChallengeCalculate, ProofFinalize};
    use crate::utils::compute_commitments;
    let L = messages.len();
    if !valid_message_vector(messages)
        || !valid_generators_cached(suite, generators, L as u128, api_id)
    {
        return Err(INVALID);
    }
    if !valid_indexes(disclosed_indexes, L as u128)
        || !valid_indexes(commitment_indexes, L as u128)
        || !disjoint(disclosed_indexes, commitment_indexes)
    {
        return Err(INVALID);
    }
    // Mandatory signature check (CoreVerify), decoding the signature and the
    // key once for the whole proof generation.
    let signature_result = octets_to_signature(signature)?;
    let W = octets_to_pubkey(PK)?;
    let verified = core_verify_decoded(
        suite,
        PK,
        &W,
        &signature_result,
        generators,
        header,
        messages,
        api_id,
    )?;

    let N = commitment_indexes.len();
    let committed_messages = select(messages, commitment_indexes)?;
    let commitment_rands = match precomputed_rands {
        None => rng.calculate_random_scalars(N)?,
        Some(values) => values.to_vec(),
    };
    let commitments = compute_commitments(suite, &committed_messages, &commitment_rands, api_id)?;

    let undisclosed_indexes = complement(disclosed_indexes, L)?;
    let U = undisclosed_indexes.len();
    let disclosed_messages = select(messages, disclosed_indexes)?;
    let undisclosed_messages = select(messages, &undisclosed_indexes)?;
    let random_scalars = rng.calculate_random_scalars(5 + U)?;
    let s_tildes = rng.calculate_random_scalars(N)?;
    // A malformed injectable source must not cause an indexing panic.
    if random_scalars.len() != 5 + U
        || random_scalars[0] == 0u64.into()
        || random_scalars[1] == 0u64.into()
    {
        return Err(INVALID);
    }
    // SI-002: all subroutine failures propagate without a partial output.
    let init_res = proof_init_with_base(
        suite,
        PK,
        &signature_result,
        generators,
        &random_scalars,
        header,
        messages,
        &undisclosed_indexes,
        commitment_indexes,
        &s_tildes,
        api_id,
        Some(&verified),
    )?;
    let c = ProofChallengeCalculate(
        suite,
        &init_res,
        &disclosed_messages,
        disclosed_indexes,
        &commitments,
        commitment_indexes,
        ph,
        api_id,
    )?;
    if c == 0u64.into() {
        return Err(INVALID);
    }
    let proof = ProofFinalize(
        suite,
        &init_res,
        c,
        signature_result.e,
        &random_scalars,
        &undisclosed_messages,
        &commitments,
        &commitment_rands,
        &s_tildes,
    )?;
    Ok((proof, (committed_messages, commitment_rands)))
}

/// Spec 3.6.4 CoreProofVerify. Expected commitments are compared in index order.
#[allow(clippy::too_many_arguments)]
pub fn CoreProofVerify(
    suite: Ciphersuite,
    PK: &[u8],
    proof: &[u8],
    generators: &[G1Projective],
    header: &[u8],
    ph: &[u8],
    disclosed_messages: &[ScalarInput],
    disclosed_indexes: &[Index],
    commitment_indexes: &[Index],
    commitments: &[G1Projective],
    api_id: &[u8],
) -> BbsResult<()> {
    let proof_result = crate::utils::octets_to_proof(proof)?;
    core_proof_verify_decoded(
        suite,
        PK,
        &proof_result,
        generators,
        header,
        ph,
        disclosed_messages,
        disclosed_indexes,
        commitment_indexes,
        commitments,
        api_id,
    )
}

/// `CoreProofVerify` for a proof already decoded by `octets_to_proof`, whose
/// points are therefore in G1.  Lets `ProofVerify` decode the proof once.
#[allow(clippy::too_many_arguments)]
pub(crate) fn core_proof_verify_decoded(
    suite: Ciphersuite,
    PK: &[u8],
    proof_result: &Proof,
    generators: &[G1Projective],
    header: &[u8],
    ph: &[u8],
    disclosed_messages: &[ScalarInput],
    disclosed_indexes: &[Index],
    commitment_indexes: &[Index],
    commitments: &[G1Projective],
    api_id: &[u8],
) -> BbsResult<()> {
    use crate::helpers::{disjoint, nonidentity};
    use crate::proof_protocol::{ProofChallengeCalculate, ProofVerifyInit};
    let W = octets_to_pubkey(PK)?;
    let R = disclosed_indexes.len();
    let L = proof_result.m_hats.len() as u128 + R as u128;
    let N = proof_result.N;
    if L > crate::params::MAX_MESSAGES || !valid_generators_cached(suite, generators, L, api_id) {
        return Err(INVALID);
    }
    if !valid_indexes(disclosed_indexes, L)
        || !valid_indexes(commitment_indexes, L)
        || !disjoint(disclosed_indexes, commitment_indexes)
    {
        return Err(INVALID);
    }
    if disclosed_messages.len() != R || !valid_message_vector(disclosed_messages) {
        return Err(INVALID);
    }
    if commitment_indexes.len() as u128 != N || commitments.len() as u128 != N {
        return Err(INVALID);
    }
    // The caller's commitments must equal the decoded (subgroup-checked)
    // ones, so they are in G1; the in_g1 check is not repeated.
    if commitments != proof_result.commitments || !nonidentity(commitments) {
        return Err(INVALID);
    }
    // SI-002: INVALID and ABORT propagate at both subroutine boundaries.
    let init_res = ProofVerifyInit(
        suite,
        PK,
        proof_result,
        generators,
        header,
        disclosed_messages,
        disclosed_indexes,
        commitment_indexes,
        api_id,
    )?;
    let c = ProofChallengeCalculate(
        suite,
        &init_res,
        disclosed_messages,
        disclosed_indexes,
        commitments,
        commitment_indexes,
        ph,
        api_id,
    )?;
    if c != proof_result.challenge {
        return Err(INVALID);
    }
    // h(A_bar, W) * h(B_bar, -BP2) == 1, as one combined pairing product.
    if !pairing_product_is_identity(&[(proof_result.A_bar, W), (proof_result.B_bar, -BP2())]) {
        return Err(INVALID);
    }
    Ok(())
}
