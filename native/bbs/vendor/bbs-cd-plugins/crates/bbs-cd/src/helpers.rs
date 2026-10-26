//! Spec 1.4 and 4.1.4: validation and notation helpers.
use crate::params::{Ciphersuite, MAX_MESSAGES};
use crate::types::{DisclosureState, Index, MessageType, ScalarInput};
use crate::{BbsResult, INVALID};
use bls12_381::{G1Affine, G1Projective, Scalar};
/// Spec 4.1.4 canonical_scalar.
pub fn canonical_scalar(x: ScalarInput) -> bool {
    x.to_scalar().is_ok()
}
/// Spec 4.1.4 nonzero_scalar.
pub fn nonzero_scalar(x: ScalarInput) -> bool {
    x.to_scalar().is_ok_and(|s| s != Scalar::zero())
}
/// Spec 4.1.4 valid_scalars.
pub fn valid_scalars(x: &[ScalarInput]) -> bool {
    x.iter().all(|s| canonical_scalar(*s))
}
/// Spec 4.1.4 valid_message_vector.
pub fn valid_message_vector(messages: &[ScalarInput]) -> bool {
    messages.len() as u128 <= MAX_MESSAGES && valid_scalars(messages)
}
/// Spec 4.1.4 valid_message_types.
pub fn valid_message_types(types: &[MessageType]) -> bool {
    types.len() as u128 <= MAX_MESSAGES
        && types
            .iter()
            .all(|t| matches!(t, MessageType::OCTETS | MessageType::SCALAR))
}
/// Spec 4.1.4 valid_indexes; integer check required by Section 5 (SI-005).
pub fn valid_indexes(I: &[Index], L: u128) -> bool {
    if L > MAX_MESSAGES {
        return false;
    }
    for a in 0..I.len() {
        let Index::Integer(value) = I[a] else {
            return false;
        };
        if value as u128 >= L {
            return false;
        }
        if a > 0 {
            let Index::Integer(previous) = I[a - 1] else {
                return false;
            };
            if previous >= value {
                return false;
            }
        }
    }
    true
}
/// Spec 4.1.4 disclosure_indexes. Preserve original increasing index order.
pub fn disclosure_indexes(
    message_disclosures: &[DisclosureState],
    L: u128,
) -> BbsResult<(Vec<Index>, Vec<Index>)> {
    if L > MAX_MESSAGES || message_disclosures.len() as u128 != L {
        return Err(INVALID);
    }
    let mut disclosed_indexes = Vec::new();
    let mut commitment_indexes = Vec::new();
    for (t, state) in message_disclosures.iter().enumerate() {
        match state {
            DisclosureState::DISCLOSE => disclosed_indexes.push(Index::Integer(t as u64)),
            DisclosureState::COMMIT => commitment_indexes.push(Index::Integer(t as u64)),
            DisclosureState::HIDE => (),
            DisclosureState::Unknown(_) => return Err(INVALID),
        }
    }
    Ok((disclosed_indexes, commitment_indexes))
}
/// Spec 1.4.1 complement. Membership is independent of input order or repetition.
///
/// Integer entries outside `0..L` have no effect. Noninteger entries are outside
/// this helper's integer-vector input domain. Protocol callers separately enforce
/// `valid_indexes`, including ordering, uniqueness, and bounds.
pub fn complement(I: &[Index], L: usize) -> BbsResult<Vec<Index>> {
    let members = I
        .iter()
        .map(|index| match index {
            Index::Integer(i) => Ok(*i),
            Index::Other(_) => Err(INVALID),
        })
        .collect::<BbsResult<std::collections::BTreeSet<_>>>()?;
    Ok((0..L)
        .map(|i| i as u64)
        .filter(|i| !members.contains(i))
        .map(Index::Integer)
        .collect())
}
/// Spec 1.4.1 position. The queried integer must occur exactly once.
pub fn position(I: &[Index], index: &Index) -> BbsResult<usize> {
    if !matches!(index, Index::Integer(_)) {
        return Err(INVALID);
    }
    let mut positions = I.iter().enumerate().filter(|(_, value)| *value == index);
    let result = positions.next().map(|(k, _)| k).ok_or(INVALID)?;
    if positions.next().is_some() {
        return Err(INVALID);
    }
    Ok(result)
}
/// Spec 1.4.1 in_g1, including caller-supplied points.
pub fn in_g1(points: &[G1Projective]) -> bool {
    points.iter().all(|p| {
        let a = G1Affine::from(p);
        bool::from(a.is_on_curve()) && bool::from(a.is_torsion_free())
    })
}
/// Spec 1.4.1 nonidentity.
pub fn nonidentity(points: &[G1Projective]) -> bool {
    points.iter().all(|p| !bool::from(p.is_identity()))
}
/// Spec 4.1.4 distinct.
pub fn distinct<T: PartialEq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .all(|(i, x)| !values[..i].contains(x))
}
/// Spec 1.4.1 disjoint.
pub fn disjoint<T: PartialEq>(a: &[T], b: &[T]) -> bool {
    a.iter().all(|x| !b.contains(x))
}
/// Spec 1.4.1 subset.
pub fn subset<T: PartialEq>(a: &[T], b: &[T]) -> bool {
    a.iter().all(|x| b.contains(x))
}
/// Spec 4.1.4 valid_generators.
pub fn valid_generators(suite: Ciphersuite, generators: &[G1Projective], L: u128) -> bool {
    L <= MAX_MESSAGES
        && generators.len() as u128 == L + 1
        && in_g1(generators)
        && nonidentity(generators)
        && disjoint(generators, &[suite.P1()])
        && distinct(generators)
}
/// Spec 1.4.1 select; callers enforce ordering and semantic bounds first.
pub fn select<T: Clone>(values: &[T], indexes: &[Index]) -> BbsResult<Vec<T>> {
    indexes
        .iter()
        .map(|index| match index {
            Index::Integer(i) => usize::try_from(*i)
                .ok()
                .and_then(|i| values.get(i))
                .cloned()
                .ok_or(INVALID),
            Index::Other(_) => Err(INVALID),
        })
        .collect()
}
/// Variable-time scalar multiplication: windowed NAF from the curve library's
/// `group` crate, built on its complete projective addition, so the result
/// equals `p * s` for every input, including the identity and zero.
///
/// Not constant-time.  Used on the holder and verifier paths only (holder
/// devices are outside the side-channel model of this deployment); the
/// issuer's `CoreSign` keeps the constant-time `*` and `dot`.
pub fn mul_vartime(p: &G1Projective, s: &Scalar) -> G1Projective {
    group::Wnaf::new().scalar(s).base(*p)
}

/// Number of 4-bit windows in a scalar (32 octets).
const MSM_WINDOWS: usize = 64;

/// Window `w` (0 = least significant) of a scalar: bits 4w..4w+3 of its
/// canonical little-endian encoding, an unsigned value in 0..=15.
fn msm_window(bytes: &[u8; 32], w: usize) -> usize {
    let byte = bytes[w / 2];
    (if w % 2 == 0 { byte & 0x0f } else { byte >> 4 }) as usize
}

/// Multi-scalar multiplication sum_i s_i * P_i (Straus' method).
///
/// Design, chosen so that every input, including adversarial ones from a
/// proof, gives exactly the group-law result:
///
/// * only the curve library's complete projective operations (`+`,
///   `double`): no affine or batched shortcuts with exceptional cases, so
///   equal points, opposite points and the identity need no special case;
/// * plain unsigned 4-bit windows of the canonical scalar encoding: no
///   signed digits, no recoding carries, exactly 64 windows per scalar;
/// * per point a table [O, P, 2P, ..., 15P] built by repeated addition;
/// * the doublings are shared by all terms (4 per window), which is where
///   the saving over separate multiplications comes from.
///
/// Variable-time: windows equal to zero are skipped.  Used on the holder and
/// verifier paths only.  Panics if the slices differ in length (an internal
/// caller bug).
pub fn msm_vartime(points: &[G1Projective], scalars: &[Scalar]) -> G1Projective {
    assert_eq!(points.len(), scalars.len(), "msm_vartime: length mismatch");
    let tables: Vec<[G1Projective; 16]> = points
        .iter()
        .map(|p| {
            let mut t = [G1Projective::identity(); 16];
            for j in 1..16 {
                t[j] = t[j - 1] + p;
            }
            t
        })
        .collect();
    let bytes: Vec<[u8; 32]> = scalars.iter().map(|s| s.to_bytes()).collect();
    let mut acc = G1Projective::identity();
    for w in (0..MSM_WINDOWS).rev() {
        if w + 1 != MSM_WINDOWS {
            for _ in 0..4 {
                acc = acc.double();
            }
        }
        for (table, b) in tables.iter().zip(&bytes) {
            let digit = msm_window(b, w);
            if digit != 0 {
                acc += table[digit];
            }
        }
    }
    acc
}

/// Spec 4.1.4 valid_generators, with a fast path for generator vectors that
/// equal the cached output of `create_generators(L + 1, api_id)`.
///
/// Those were derived by hash-to-curve with cofactor clearing (so they are in
/// G1) and checked for identity, `P1` and repetition when they were cached,
/// so they satisfy every condition of `valid_generators`; the subgroup
/// checks are not repeated for them.  Any other vector gets the full check,
/// so the result equals `valid_generators(suite, generators, L)` always.
pub(crate) fn valid_generators_cached(
    suite: Ciphersuite,
    generators: &[G1Projective],
    L: u128,
    api_id: &[u8],
) -> bool {
    if L > MAX_MESSAGES || generators.len() as u128 != L + 1 {
        return false;
    }
    match crate::utils::cached_generators(suite, L + 1, api_id) {
        Some(cached) if cached.as_slice() == generators => true,
        _ => valid_generators(suite, generators, L),
    }
}

/// Spec 1.4.1 dot; the empty product is the G1 identity.
pub fn dot(points: &[G1Projective], scalars: &[ScalarInput]) -> BbsResult<G1Projective> {
    if points.len() != scalars.len() {
        return Err(INVALID);
    }
    let mut result = G1Projective::identity();
    for (point, scalar) in points.iter().zip(scalars) {
        result += point * scalar.to_scalar()?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{COMMIT, DISCLOSE, HIDE};

    /// Spec 4.1.4. Unknown states and schema length errors are INVALID.
    #[test]
    fn disclosure_indexes_checks() {
        assert_eq!(
            disclosure_indexes(&[COMMIT, HIDE, DISCLOSE, COMMIT], 4).unwrap(),
            (vec![2u64.into()], vec![0u64.into(), 3u64.into()])
        );
        assert_eq!(disclosure_indexes(&[], 0).unwrap(), (vec![], vec![]));
        assert_eq!(disclosure_indexes(&[], 1), Err(INVALID));
        assert_eq!(disclosure_indexes(&[], MAX_MESSAGES + 1), Err(INVALID));
        assert_eq!(
            disclosure_indexes(&[DisclosureState::Unknown("SHOW".into())], 1),
            Err(INVALID)
        );
    }

    /// Spec 1.4.1. Empty complements and unique positions preserve indexes.
    #[test]
    fn complement_and_position() {
        assert_eq!(complement(&[], 0).unwrap(), vec![]);
        let indexes = [0u64.into(), 2u64.into()];
        assert_eq!(complement(&indexes, 4).unwrap(), [1u64.into(), 3u64.into()]);
        assert_eq!(position(&indexes, &2u64.into()).unwrap(), 1);
        assert_eq!(position(&indexes, &1u64.into()), Err(INVALID));
        assert_eq!(
            position(&[0u64.into(), 0u64.into()], &0u64.into()),
            Err(INVALID)
        );
        assert_eq!(complement(&[Index::Other("1.5".into())], 3), Err(INVALID));
    }

    /// Spec 1.4.1. Complement uses set membership, not protocol index validation.
    #[test]
    fn complement_accepts_unsorted_repeated_and_irrelevant_integers() {
        let cases: &[(&[u64], usize, &[u64])] = &[
            (&[2, 1], 3, &[0]),
            (&[1, 1], 3, &[0, 2]),
            (&[3, u64::MAX], 3, &[0, 1, 2]),
            (&[2, 0, 2, 1], 3, &[]),
            (&[], 3, &[0, 1, 2]),
            (&[0, 0, u64::MAX], 0, &[]),
        ];
        for (input, length, expected) in cases {
            let indexes: Vec<Index> = input.iter().copied().map(Into::into).collect();
            let expected: Vec<Index> = expected.iter().copied().map(Into::into).collect();
            assert_eq!(complement(&indexes, *length).unwrap(), expected);
        }
        // Core callers still require canonical indexes under Section 4.1.4.
        for indexes in [
            vec![2u64.into(), 1u64.into()],
            vec![1u64.into(), 1u64.into()],
            vec![3u64.into()],
        ] {
            assert!(!valid_indexes(&indexes, 3));
        }
    }
}
