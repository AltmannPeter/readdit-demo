//! Spec 4.1–4.2: generator derivation, message mapping, and typed encodings.

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use bls12_381::{G1Projective, G2Affine, G2Projective};

use crate::helpers::{
    canonical_scalar, in_g1, msm_vartime, nonidentity, nonzero_scalar, valid_message_types,
    valid_scalars,
};
use crate::params::{
    Ciphersuite, EXPAND_LEN, MAX_MESSAGES, OCTET_POINT_LENGTH, OCTET_SCALAR_LENGTH,
};
use crate::primitives::{
    I2OSP, decode_G1, expand_message, hash_to_curve_g1, point_to_octets_E1, point_to_octets_E2,
    scalar_from_wide,
};
use crate::types::{Message, MessageType, Proof, ScalarInput, Signature};
use crate::{BbsError, BbsResult, INVALID};

type GeneratorCache = HashMap<(Ciphersuite, u128, Vec<u8>), Vec<G1Projective>>;
static GENERATORS: OnceLock<Mutex<GeneratorCache>> = OnceLock::new();

/// Spec 4.2.2 hash_to_scalar. Hash and reduce; zero remains a valid output.
pub fn hash_to_scalar(suite: Ciphersuite, msg: &[u8], dst: &[u8]) -> BbsResult<ScalarInput> {
    if dst.len() > 255 {
        return Err(BbsError::Abort("hash_to_scalar DST exceeds 255 octets"));
    }
    #[cfg(test)]
    if let Some(result) = hash_test_hook::substitute(suite, dst) {
        return result;
    }
    let uniform_bytes = expand_message(suite, msg, dst, EXPAND_LEN)?;
    let bytes: &[u8; EXPAND_LEN] = uniform_bytes
        .as_slice()
        .try_into()
        .map_err(|_| BbsError::Abort("unexpected expansion length"))?;
    Ok(scalar_from_wide(bytes).into())
}

/// Spec 4.2.2 test machinery: substitute one selected hash call in this thread.
#[cfg(test)]
pub(crate) mod hash_test_hook {
    use std::{cell::RefCell, marker::PhantomData, rc::Rc};

    use super::*;

    struct Injection {
        suite: Ciphersuite,
        dst: Vec<u8>,
        invocation: usize,
        result: BbsResult<ScalarInput>,
        matching_calls: usize,
        hits: usize,
    }

    thread_local! {
        static INJECTION: RefCell<Option<Injection>> = const { RefCell::new(None) };
    }

    // The Rc marker prevents moving the cleanup guard to another thread.
    pub(crate) struct HashOverride(PhantomData<Rc<()>>);

    impl HashOverride {
        /// Spec 4.2.2 test machinery: target an exact suite, DST and invocation.
        pub(crate) fn new(
            suite: Ciphersuite,
            dst: Vec<u8>,
            invocation: usize,
            result: BbsResult<ScalarInput>,
        ) -> Self {
            assert!(invocation > 0);
            INJECTION.with(|slot| {
                let mut slot = slot.borrow_mut();
                assert!(
                    slot.is_none(),
                    "hash overrides must not overlap in one thread"
                );
                *slot = Some(Injection {
                    suite,
                    dst,
                    invocation,
                    result,
                    matching_calls: 0,
                    hits: 0,
                });
            });
            Self(PhantomData)
        }

        /// Spec 4.2.2 test machinery: prove which matching call was substituted.
        pub(crate) fn counts(&self) -> (usize, usize) {
            INJECTION.with(|slot| {
                let slot = slot.borrow();
                let injection = slot.as_ref().expect("live hash override");
                (injection.matching_calls, injection.hits)
            })
        }
    }

    impl Drop for HashOverride {
        /// Spec 4.2.2 test machinery: restore normal hashing, including on unwind.
        fn drop(&mut self) {
            INJECTION.with(|slot| *slot.borrow_mut() = None);
        }
    }

    /// Spec 4.2.2 test machinery: leave other suites, DSTs and calls untouched.
    pub(super) fn substitute(suite: Ciphersuite, dst: &[u8]) -> Option<BbsResult<ScalarInput>> {
        INJECTION.with(|slot| {
            let mut slot = slot.borrow_mut();
            let injection = slot.as_mut()?;
            if suite != injection.suite || dst != injection.dst {
                return None;
            }
            injection.matching_calls += 1;
            if injection.matching_calls != injection.invocation {
                return None;
            }
            injection.hits += 1;
            Some(injection.result)
        })
    }
}

/// Spec 4.1.1 create_generators. Cache successful derivations without retries.
pub fn create_generators(
    suite: Ciphersuite,
    count: u128,
    api_id: &[u8],
) -> BbsResult<Vec<G1Projective>> {
    if count > u64::MAX as u128 {
        return Err(BbsError::Abort("generator count exceeds u64"));
    }
    let cache = GENERATORS.get_or_init(|| Mutex::new(HashMap::new()));
    let key = (suite, count, api_id.to_vec());
    if let Some(generators) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
        return Ok(generators.clone());
    }
    let seed_dst = [api_id, b"SIG_GENERATOR_SEED_"].concat();
    let generator_dst = [api_id, b"SIG_GENERATOR_DST_"].concat();
    let generator_seed = [api_id, b"MESSAGE_GENERATOR_SEED"].concat();
    let mut v = expand_message(suite, &generator_seed, &seed_dst, EXPAND_LEN)?;
    let mut generators = Vec::new();
    for i in 1..=count {
        let input = [v.as_slice(), &I2OSP(i, 8)?].concat();
        v = expand_message(suite, &input, &seed_dst, EXPAND_LEN)?;
        let G = hash_to_curve_g1(suite, &v, &generator_dst)?;
        if bool::from(G.is_identity()) || G == suite.P1() || generators.contains(&G) {
            return Err(INVALID);
        }
        generators.push(G);
    }
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, generators.clone());
    Ok(generators)
}

/// The cached output of `create_generators(count, api_id)`, if it has been
/// derived in this process.  Never derives; see `valid_generators_cached`.
pub(crate) fn cached_generators(
    suite: Ciphersuite,
    count: u128,
    api_id: &[u8],
) -> Option<Vec<G1Projective>> {
    let cache = GENERATORS.get()?;
    let key = (suite, count, api_id.to_vec());
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .cloned()
}

/// Spec 4.1.1 commitment_generators. Y_0 multiplies messages, Y_1 openings.
pub fn commitment_generators(
    suite: Ciphersuite,
    api_id: &[u8],
) -> BbsResult<(G1Projective, G1Projective)> {
    let generators = create_generators(suite, 2, &[b"COM_DIS_", api_id].concat())?;
    Ok((generators[0], generators[1]))
}

/// Spec 4.1.1 compute_commitments. Bind each message with its own opening.
pub fn compute_commitments(
    suite: Ciphersuite,
    committed_scalars: &[ScalarInput],
    commitment_rands: &[ScalarInput],
    api_id: &[u8],
) -> BbsResult<Vec<G1Projective>> {
    let N = committed_scalars.len();
    if commitment_rands.len() != N || !valid_scalars(commitment_rands) {
        return Err(INVALID);
    }
    let (Y_0, Y_1) = commitment_generators(suite, api_id)?;
    let mut commitments = Vec::new();
    for b in 0..N {
        let C = msm_vartime(
            &[Y_0, Y_1],
            &[
                committed_scalars[b].to_scalar()?,
                commitment_rands[b].to_scalar()?,
            ],
        );
        if bool::from(C.is_identity()) {
            return Err(INVALID);
        }
        commitments.push(C);
    }
    Ok(commitments)
}

/// Spec 4.1.5 presentation_context. Encode ordered commitments with both lengths.
pub fn presentation_context(ph: &[u8], commitments: &[G1Projective]) -> BbsResult<Vec<u8>> {
    presentation_context_impl(ph, commitments, true)
}

/// `presentation_context` for commitments the caller has already checked to
/// be in G1 (decoded, or compared equal to decoded points).  Same output.
pub(crate) fn presentation_context_in_g1(
    ph: &[u8],
    commitments: &[G1Projective],
) -> BbsResult<Vec<u8>> {
    presentation_context_impl(ph, commitments, false)
}

fn presentation_context_impl(
    ph: &[u8],
    commitments: &[G1Projective],
    check_g1: bool,
) -> BbsResult<Vec<u8>> {
    let N = commitments.len();
    if ph.len() as u128 > u64::MAX as u128 || N as u128 > u64::MAX as u128 {
        return Err(BbsError::Abort("presentation context length exceeds u64"));
    }
    if (check_g1 && !in_g1(commitments)) || !nonidentity(commitments) {
        return Err(INVALID);
    }
    debug_assert!(
        in_g1(commitments),
        "presentation_context_in_g1: point outside G1"
    );
    Ok([
        I2OSP(ph.len() as u128, 8)?.as_slice(),
        ph,
        I2OSP(N as u128, 8)?.as_slice(),
        serialize_in_g1(&commitments.iter().map(Field::G1).collect::<Vec<_>>())?.as_slice(),
    ]
    .concat())
}

/// Spec 4.1.2 messages_to_scalars. Preserve schema order and scalar values.
pub fn messages_to_scalars(
    suite: Ciphersuite,
    messages: &[Message],
    message_types: &[MessageType],
    api_id: &[u8],
) -> BbsResult<Vec<ScalarInput>> {
    let L = messages.len();
    if L as u128 > MAX_MESSAGES {
        return Err(BbsError::Abort("message count exceeds 2^64 - 2"));
    }
    if message_types.len() != L || !valid_message_types(message_types) {
        return Err(INVALID);
    }
    let map_dst = [api_id, b"MAP_MSG_TO_SCALAR_AS_HASH_"].concat();
    let mut message_scalars = Vec::new();
    for t in 0..L {
        let msg = &messages[t];
        match (&message_types[t], msg) {
            (MessageType::OCTETS, Message::Octets(octets)) => {
                message_scalars.push(hash_to_scalar(suite, octets, &map_dst)?);
            }
            (MessageType::SCALAR, Message::Scalar(scalar)) if canonical_scalar(*scalar) => {
                message_scalars.push(*scalar);
            }
            _ => return Err(INVALID),
        }
    }
    Ok(message_scalars)
}

/// Spec 4.2.3 calculate_domain. L = 0 is permitted by this profile.
pub fn calculate_domain(
    suite: Ciphersuite,
    PK: &[u8],
    Q_1: &G1Projective,
    H_Points: &[G1Projective],
    header: &[u8],
    api_id: &[u8],
) -> BbsResult<ScalarInput> {
    calculate_domain_impl(suite, PK, Q_1, H_Points, header, api_id, true)
}

/// `calculate_domain` for generators that already passed `valid_generators`
/// (or `valid_generators_cached`) in the same call.  Same output.
pub(crate) fn calculate_domain_in_g1(
    suite: Ciphersuite,
    PK: &[u8],
    Q_1: &G1Projective,
    H_Points: &[G1Projective],
    header: &[u8],
    api_id: &[u8],
) -> BbsResult<ScalarInput> {
    calculate_domain_impl(suite, PK, Q_1, H_Points, header, api_id, false)
}

fn calculate_domain_impl(
    suite: Ciphersuite,
    PK: &[u8],
    Q_1: &G1Projective,
    H_Points: &[G1Projective],
    header: &[u8],
    api_id: &[u8],
    check_g1: bool,
) -> BbsResult<ScalarInput> {
    let L = H_Points.len();
    if L as u128 > u64::MAX as u128 || header.len() as u128 > u64::MAX as u128 {
        return Err(BbsError::Abort("domain count or header length exceeds u64"));
    }
    let mut dom_array = vec![Field::U64(L as u128), Field::G1(Q_1)];
    dom_array.extend(H_Points.iter().map(Field::G1));
    let dom_octs = [serialize_impl(&dom_array, check_g1)?.as_slice(), api_id].concat();
    let dom_input = [PK, &dom_octs, &I2OSP(header.len() as u128, 8)?, header].concat();
    hash_to_scalar(suite, &dom_input, &[api_id, b"H2S_"].concat())
}

/// Spec 4.2.4.1: a field's definition determines scalar versus integer encoding.
pub enum Field<'a> {
    G1(&'a G1Projective),
    G2(&'a G2Projective),
    Scalar(ScalarInput),
    U64(u128),
}

/// Spec 4.2.4.1 serialize. Flattened, explicitly typed canonical encoding.
pub fn serialize(input_array: &[Field<'_>]) -> BbsResult<Vec<u8>> {
    serialize_impl(input_array, true)
}

/// `serialize` for G1 points the caller has already checked to be in G1:
/// generators validated in the same call, decoded points, and points
/// computed from those (G1 is closed under addition and scalar
/// multiplication).  Identical output; every other check is kept.
pub(crate) fn serialize_in_g1(input_array: &[Field<'_>]) -> BbsResult<Vec<u8>> {
    serialize_impl(input_array, false)
}

fn serialize_impl(input_array: &[Field<'_>], check_g1: bool) -> BbsResult<Vec<u8>> {
    let mut octets_result = Vec::new();
    for el in input_array {
        match el {
            Field::G1(point) => {
                if check_g1 && !in_g1(&[**point]) {
                    return Err(INVALID);
                }
                debug_assert!(in_g1(&[**point]), "serialize_in_g1: point outside G1");
                octets_result.extend_from_slice(&point_to_octets_E1(point));
            }
            Field::G2(point) => {
                let affine = G2Affine::from(*point);
                if !bool::from(affine.is_on_curve()) || !bool::from(affine.is_torsion_free()) {
                    return Err(INVALID);
                }
                octets_result.extend_from_slice(&point_to_octets_E2(point));
            }
            Field::Scalar(scalar) => {
                if !canonical_scalar(*scalar) {
                    return Err(INVALID);
                }
                octets_result.extend_from_slice(&scalar.0);
            }
            Field::U64(integer) => {
                if *integer > u64::MAX as u128 {
                    return Err(INVALID);
                }
                octets_result.extend_from_slice(&I2OSP(*integer, 8)?);
            }
        }
    }
    Ok(octets_result)
}

/// Spec 4.2.4.2 signature_to_octets. Reject identity A and zero or invalid e.
pub fn signature_to_octets(signature: &Signature) -> BbsResult<Vec<u8>> {
    let Signature { A, e } = signature;
    if !in_g1(&[*A]) || bool::from(A.is_identity()) || !nonzero_scalar(*e) {
        return Err(INVALID);
    }
    Ok([point_to_octets_E1(A).as_slice(), &e.0].concat())
}

/// Spec 4.2.4.3 octets_to_signature. Exact length, validated point and scalar.
pub fn octets_to_signature(signature_octets: &[u8]) -> BbsResult<Signature> {
    if signature_octets.len() != 48 + 32 {
        return Err(INVALID);
    }
    let A = decode_G1(&signature_octets[..48], false)?;
    let e = ScalarInput(signature_octets[48..80].try_into().map_err(|_| INVALID)?);
    if !nonzero_scalar(e) {
        return Err(INVALID);
    }
    Ok(Signature { A, e })
}

/// Spec 4.2.4.4 valid_proof_tuple. The Rust type fixes the eleven-field shape.
pub fn valid_proof_tuple(proof: &Proof) -> bool {
    let mut points = vec![proof.A_bar, proof.B_bar, proof.D];
    points.extend_from_slice(&proof.commitments);
    in_g1(&points) && valid_proof_tuple_in_g1(proof)
}

/// `valid_proof_tuple` for a proof whose points are known to be in G1
/// (decoded by `decode_G1`, or computed by this crate from such points).
/// Every other condition is checked; the result equals `valid_proof_tuple`.
pub(crate) fn valid_proof_tuple_in_g1(proof: &Proof) -> bool {
    let U = proof.m_hats.len() as u128;
    if proof.N > MAX_MESSAGES
        || U > MAX_MESSAGES
        || proof.N > U
        || proof.commitments.len() as u128 != proof.N
        || proof.s_hats.len() as u128 != proof.N
    {
        return false;
    }
    let mut points = vec![proof.A_bar, proof.B_bar, proof.D];
    points.extend_from_slice(&proof.commitments);
    let mut scalars = vec![proof.e_hat, proof.r1_hat, proof.r3_hat];
    scalars.extend_from_slice(&proof.m_hats);
    scalars.extend_from_slice(&proof.s_hats);
    scalars.push(proof.challenge);
    debug_assert!(in_g1(&points), "valid_proof_tuple_in_g1: point outside G1");
    nonidentity(&points)
        && valid_scalars(&scalars)
        && scalars.iter().all(|scalar| *scalar != ScalarInput::from(0))
}

/// Spec 4.2.4.4 proof_to_octets. N is always an eight-octet prefix.
pub fn proof_to_octets(proof: &Proof) -> BbsResult<Vec<u8>> {
    if !valid_proof_tuple(proof) {
        return Err(INVALID);
    }
    proof_to_octets_in_g1(proof)
}

/// `proof_to_octets` for a proof computed by this crate from points in G1
/// (`ProofFinalize`).  Same output, same non-subgroup checks.
pub(crate) fn proof_to_octets_in_g1(proof: &Proof) -> BbsResult<Vec<u8>> {
    if !valid_proof_tuple_in_g1(proof) {
        return Err(INVALID);
    }
    let mut fields = vec![
        Field::G1(&proof.A_bar),
        Field::G1(&proof.B_bar),
        Field::G1(&proof.D),
        Field::Scalar(proof.e_hat),
        Field::Scalar(proof.r1_hat),
        Field::Scalar(proof.r3_hat),
    ];
    fields.extend(proof.m_hats.iter().copied().map(Field::Scalar));
    fields.extend(proof.commitments.iter().map(Field::G1));
    fields.extend(proof.s_hats.iter().copied().map(Field::Scalar));
    fields.push(Field::Scalar(proof.challenge));
    Ok([I2OSP(proof.N, 8)?, serialize_in_g1(&fields)?].concat())
}

/// Spec 4.2.4.5. Reject failed fixed-width reads rather than filling missing bytes.
fn proof_read<'a>(octets: &'a [u8], offset: &mut usize, count: usize) -> BbsResult<&'a [u8]> {
    let end = offset.checked_add(count).ok_or(INVALID)?;
    let result = octets.get(*offset..end).ok_or(INVALID)?;
    *offset = end;
    Ok(result)
}

/// Spec 4.2.4.5. Read a canonical, nonzero scalar without reduction.
fn proof_read_scalar(octets: &[u8], offset: &mut usize) -> BbsResult<ScalarInput> {
    let x = ScalarInput(
        proof_read(octets, offset, OCTET_SCALAR_LENGTH)?
            .try_into()
            .map_err(|_| INVALID)?,
    );
    if !nonzero_scalar(x) {
        return Err(INVALID);
    }
    Ok(x)
}

/// Spec 4.2.4.5 octets_to_proof. Check every dimension before allocating or decoding.
pub fn octets_to_proof(proof_octets: &[u8]) -> BbsResult<Proof> {
    let total = proof_octets.len();
    let P = OCTET_POINT_LENGTH;
    let S = OCTET_SCALAR_LENGTH;
    let minimum = 8 + 3 * P + 4 * S;
    if total < minimum {
        return Err(INVALID);
    }
    let N = u64::from_be_bytes(proof_octets[..8].try_into().map_err(|_| INVALID)?) as u128;
    if N > MAX_MESSAGES || N > ((total - minimum) / (P + S)) as u128 {
        return Err(INVALID);
    }
    let count = usize::try_from(N).map_err(|_| INVALID)?;
    let base = count
        .checked_mul(P + S)
        .and_then(|length| minimum.checked_add(length))
        .ok_or(INVALID)?;
    let remaining = total.checked_sub(base).ok_or(INVALID)?;
    if remaining % S != 0 {
        return Err(INVALID);
    }
    let U = remaining / S;
    if U as u128 > MAX_MESSAGES || N > U as u128 {
        return Err(INVALID);
    }
    let mut offset = 8;
    let mut points = Vec::new();
    for _i in 0..3 {
        points.push(decode_G1(proof_read(proof_octets, &mut offset, P)?, false)?);
    }
    let mut responses = Vec::new();
    for _i in 0..U.checked_add(3).ok_or(INVALID)? {
        responses.push(proof_read_scalar(proof_octets, &mut offset)?);
    }
    let mut commitments = Vec::new();
    for _b in 0..count {
        commitments.push(decode_G1(proof_read(proof_octets, &mut offset, P)?, false)?);
    }
    let mut s_hats = Vec::new();
    for _b in 0..count {
        s_hats.push(proof_read_scalar(proof_octets, &mut offset)?);
    }
    let challenge = proof_read_scalar(proof_octets, &mut offset)?;
    if offset != total {
        return Err(INVALID);
    }
    let proof = Proof {
        A_bar: points[0],
        B_bar: points[1],
        D: points[2],
        e_hat: responses[0],
        r1_hat: responses[1],
        r3_hat: responses[2],
        m_hats: responses[3..].to_vec(),
        N,
        commitments,
        s_hats,
        challenge,
    };
    // Every point came from decode_G1, which checked the subgroup.
    if !valid_proof_tuple_in_g1(&proof) {
        return Err(INVALID);
    }
    Ok(proof)
}

/// Spec 4.2.1 calculate_random_scalars. Draw independent samples in call order.
pub fn calculate_random_scalars(
    count: usize,
    rng: &mut dyn FnMut(&mut [u8]) -> BbsResult<()>,
) -> BbsResult<Vec<ScalarInput>> {
    let mut random_scalars = Vec::new();
    for _i in 1..=count {
        let mut octets = [0; EXPAND_LEN];
        rng(&mut octets)?;
        random_scalars.push(scalar_from_wide(&octets).into());
    }
    Ok(random_scalars)
}

/// Spec 4.2.1 get_random. Obtain bytes from the operating system CSPRNG.
pub fn get_random(output: &mut [u8]) -> BbsResult<()> {
    getrandom::fill(output).map_err(|_| BbsError::Abort("operating system random source failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::R;

    /// Spec 4.2.4.4. Build a small proof tuple without claiming proof validity.
    fn sample_proof(U: usize, N: usize) -> Proof {
        Proof {
            A_bar: G1Projective::generator(),
            B_bar: G1Projective::generator() * bls12_381::Scalar::from(2),
            D: G1Projective::generator() * bls12_381::Scalar::from(3),
            e_hat: 1u64.into(),
            r1_hat: 2u64.into(),
            r3_hat: 3u64.into(),
            m_hats: vec![4u64.into(); U],
            N: N as u128,
            commitments: vec![G1Projective::generator(); N],
            s_hats: vec![5u64.into(); N],
            challenge: 6u64.into(),
        }
    }

    /// Spec 4.1.1. Commitment generator roles, opening ranges, and identity exclusion.
    #[test]
    fn commitment_computation() {
        for suite in [Ciphersuite::Sha256, Ciphersuite::Shake256] {
            let api = suite.api_id();
            let (Y_0, Y_1) = commitment_generators(suite, &api).unwrap();
            assert_eq!(
                compute_commitments(suite, &[2u64.into()], &[3u64.into()], &api).unwrap(),
                [Y_0 * bls12_381::Scalar::from(2) + Y_1 * bls12_381::Scalar::from(3)]
            );
            assert_eq!(
                compute_commitments(suite, &[1u64.into()], &[0u64.into()], &api).unwrap(),
                [Y_0]
            );
            assert!(
                compute_commitments(suite, &[], &[], &api)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                compute_commitments(suite, &[0u64.into()], &[0u64.into()], &api),
                Err(INVALID)
            );
            assert_eq!(
                compute_commitments(suite, &[1u64.into()], &[], &api),
                Err(INVALID)
            );
            assert_eq!(
                compute_commitments(suite, &[1u64.into()], &[ScalarInput(R)], &api),
                Err(INVALID)
            );
            assert_eq!(
                compute_commitments(suite, &[ScalarInput(R)], &[1u64.into()], &api),
                Err(INVALID)
            );
        }
    }

    /// Spec 4.1.5. Context encodes both counts and the original point order exactly.
    #[test]
    fn presentation_context_bytes() {
        assert_eq!(presentation_context(b"", &[]).unwrap(), [0; 16]);
        assert_eq!(
            presentation_context(b"abc", &[]).unwrap(),
            [
                0, 0, 0, 0, 0, 0, 0, 3, b'a', b'b', b'c', 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
        let points = [
            G1Projective::generator(),
            G1Projective::generator() * bls12_381::Scalar::from(2),
        ];
        let mut expected = vec![0, 0, 0, 0, 0, 0, 0, 2, 0xff, 0x00, 0, 0, 0, 0, 0, 0, 0, 2];
        expected.extend_from_slice(&point_to_octets_E1(&points[0]));
        expected.extend_from_slice(&point_to_octets_E1(&points[1]));
        assert_eq!(
            presentation_context(&[0xff, 0x00], &points).unwrap(),
            expected
        );
        assert_ne!(
            presentation_context(&[0xff, 0x00], &[points[1], points[0]]).unwrap(),
            expected
        );
        assert_eq!(
            presentation_context(b"", &[G1Projective::identity()]),
            Err(INVALID)
        );
    }

    /// Spec 4.2.4.4–4.2.4.5. Empty undisclosed and commitment vectors retain N.
    #[test]
    fn proof_encoding_round_trips() {
        for (U, N) in [(0, 0), (2, 0), (2, 1), (2, 2)] {
            let proof = sample_proof(U, N);
            assert!(valid_proof_tuple(&proof));
            let encoded = proof_to_octets(&proof).unwrap();
            assert_eq!(&encoded[..8], &(N as u64).to_be_bytes());
            assert_eq!(encoded.len(), 8 + 3 * 48 + (4 + U) * 32 + N * (48 + 32));
            assert_eq!(octets_to_proof(&encoded).unwrap(), proof);
        }
        let mut proof = sample_proof(1, 1);
        proof.N = MAX_MESSAGES + 1;
        assert!(!valid_proof_tuple(&proof));
        assert_eq!(proof_to_octets(&proof), Err(INVALID));
        proof.N = 2;
        assert!(!valid_proof_tuple(&proof));
        proof.N = 0;
        assert!(!valid_proof_tuple(&proof));
        proof.N = 1;
        proof.s_hats.clear();
        assert!(!valid_proof_tuple(&proof));
    }

    /// Spec 4.2.4.5. Counts are rejected before their implied allocations or reads.
    #[test]
    fn proof_parser_dimensions() {
        let encoded = proof_to_octets(&sample_proof(0, 0)).unwrap();
        for total in 0..encoded.len() {
            assert_eq!(octets_to_proof(&encoded[..total]), Err(INVALID));
        }
        for count in [1, u64::MAX - 1, u64::MAX] {
            let mut malformed = encoded.clone();
            malformed[..8].copy_from_slice(&count.to_be_bytes());
            assert_eq!(octets_to_proof(&malformed), Err(INVALID));
        }
        let encoded = proof_to_octets(&sample_proof(2, 1)).unwrap();
        // total 360 has room for the N=1 overhead but infers U=0, so N > U.
        assert_eq!(octets_to_proof(&encoded[..360]), Err(INVALID));
        let mut extra = encoded.clone();
        extra.push(0);
        assert_eq!(octets_to_proof(&extra), Err(INVALID));
        assert_eq!(octets_to_proof(&encoded[..encoded.len() - 1]), Err(INVALID));
        let mut offset = usize::MAX;
        assert_eq!(proof_read(&[], &mut offset, 1), Err(INVALID));
    }

    /// Spec 4.2.4.4–4.2.4.5. Every response and the challenge must be canonical and nonzero.
    #[test]
    fn proof_parser_scalar_checks() {
        let proof = sample_proof(2, 1);
        let encoded = proof_to_octets(&proof).unwrap();
        for offset in [152, 184, 216, 248, 280, 360, 392] {
            for scalar in [[0; 32], R, [0xff; 32]] {
                let mut malformed = encoded.clone();
                malformed[offset..offset + 32].copy_from_slice(&scalar);
                assert_eq!(octets_to_proof(&malformed), Err(INVALID));
            }
        }
        for field in 0..7 {
            let mut invalid = proof.clone();
            let scalar = match field {
                0 => &mut invalid.e_hat,
                1 => &mut invalid.r1_hat,
                2 => &mut invalid.r3_hat,
                3 => &mut invalid.m_hats[0],
                4 => &mut invalid.m_hats[1],
                5 => &mut invalid.s_hats[0],
                _ => &mut invalid.challenge,
            };
            *scalar = 0u64.into();
            assert!(!valid_proof_tuple(&invalid));
            assert_eq!(proof_to_octets(&invalid), Err(INVALID));
        }
    }

    /// Spec 4.2.4.6. Each proof and commitment point gets the full decode checks.
    #[test]
    fn proof_parser_point_checks() {
        let encoded = proof_to_octets(&sample_proof(2, 1)).unwrap();
        let identity = point_to_octets_E1(&G1Projective::identity());
        let mut noncanonical = identity;
        noncanonical[47] = 1;
        let mut torsion = [0; 48];
        torsion[0] = 0x80;
        for offset in [8, 56, 104, 312] {
            for point in [identity, noncanonical, torsion, [0xff; 48]] {
                let mut malformed = encoded.clone();
                malformed[offset..offset + 48].copy_from_slice(&point);
                assert_eq!(octets_to_proof(&malformed), Err(INVALID));
            }
        }
        for field in 0..4 {
            let mut proof = sample_proof(2, 1);
            let point = match field {
                0 => &mut proof.A_bar,
                1 => &mut proof.B_bar,
                2 => &mut proof.D,
                _ => &mut proof.commitments[0],
            };
            *point = G1Projective::identity();
            assert!(!valid_proof_tuple(&proof));
            assert_eq!(proof_to_octets(&proof), Err(INVALID));
        }
    }

    /// Spec 4.2.4.1. A small scalar and a small integer have distinct lengths.
    #[test]
    fn typed_serialization() {
        let scalar = ScalarInput::from(1);
        assert_eq!(serialize(&[Field::Scalar(scalar)]).unwrap(), scalar.0);
        assert_eq!(
            serialize(&[Field::U64(1)]).unwrap(),
            [0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(serialize(&[Field::Scalar(ScalarInput(R))]), Err(INVALID));
        assert_eq!(serialize(&[Field::U64(u64::MAX as u128 + 1)]), Err(INVALID));
    }

    /// Spec 4.2.4.2–4.2.4.3. Signature wire validation preserves both fields.
    #[test]
    fn signature_encoding() {
        let signature = Signature {
            A: G1Projective::generator(),
            e: 1u64.into(),
        };
        let encoded = signature_to_octets(&signature).unwrap();
        let decoded = octets_to_signature(&encoded).unwrap();
        assert_eq!(decoded.A, signature.A);
        assert_eq!(decoded.e, signature.e);
        let mut zero = encoded.clone();
        zero[48..].fill(0);
        assert!(octets_to_signature(&zero).is_err());
        let mut out_of_range = encoded.clone();
        out_of_range[48..].copy_from_slice(&R);
        assert!(octets_to_signature(&out_of_range).is_err());
        assert!(octets_to_signature(&encoded[..79]).is_err());
        assert!(
            signature_to_octets(&Signature {
                A: G1Projective::identity(),
                e: 1u64.into()
            })
            .is_err()
        );
    }

    /// Spec 4.1.2. Schema types and canonicality reject substitution and reduction.
    #[test]
    fn typed_message_mapping() {
        for suite in [Ciphersuite::Sha256, Ciphersuite::Shake256] {
            let api = suite.api_id();
            let messages = [Message::Octets(vec![]), Message::Scalar(7u64.into())];
            let mapped = messages_to_scalars(
                suite,
                &messages,
                &[MessageType::OCTETS, MessageType::SCALAR],
                &api,
            )
            .unwrap();
            assert_eq!(mapped[1], 7u64.into());
            assert!(
                messages_to_scalars(
                    suite,
                    &messages,
                    &[MessageType::SCALAR, MessageType::OCTETS],
                    &api
                )
                .is_err()
            );
            assert!(
                messages_to_scalars(
                    suite,
                    &[Message::Scalar(ScalarInput(R))],
                    &[MessageType::SCALAR],
                    &api
                )
                .is_err()
            );
            assert!(matches!(
                hash_to_scalar(suite, b"", &[0; 256]),
                Err(BbsError::Abort(_))
            ));
        }
    }

    /// Spec 4.1.1, 4.2.3. Successful caching preserves generator prefixes and L0.
    #[test]
    fn generators_and_empty_domain() {
        for suite in [Ciphersuite::Sha256, Ciphersuite::Shake256] {
            let api = suite.api_id();
            assert!(create_generators(suite, 0, &api).unwrap().is_empty());
            let two = create_generators(suite, 2, &api).unwrap();
            assert_eq!(create_generators(suite, 1, &api).unwrap(), two[..1]);
            assert_eq!(create_generators(suite, 2, &api).unwrap(), two);
            assert!(matches!(
                create_generators(suite, u64::MAX as u128 + 1, &api),
                Err(BbsError::Abort(_))
            ));
            assert!(calculate_domain(suite, b"pk", &two[0], &[], b"", &api).is_ok());
        }
    }

    /// Spec 4.2.1. Each scalar uses a fresh draw and failures propagate.
    #[test]
    fn random_sample_order() {
        let mut calls = 0u8;
        let values = calculate_random_scalars(2, &mut |output| {
            calls += 1;
            output.fill(0);
            output[47] = calls;
            Ok(())
        })
        .unwrap();
        assert_eq!(values, [1u64.into(), 2u64.into()]);
        assert_eq!(calls, 2);
        assert!(
            calculate_random_scalars(0, &mut |_| panic!("no draw for zero count"))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            calculate_random_scalars(1, &mut |_| Err(BbsError::Abort("rng failed"))),
            Err(BbsError::Abort("rng failed"))
        );
    }
}
