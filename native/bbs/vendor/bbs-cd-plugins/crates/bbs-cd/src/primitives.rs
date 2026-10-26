//! Spec Sections 1.4, 1.5 and 4.2.4.6: hashing, conversions, and point decoding.

use bls12_381::{
    G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
    hash_to_curve::{ExpandMessage, ExpandMsgXmd, ExpandMsgXof, HashToCurve},
};
use sha2::{Sha256, digest::generic_array::typenum::U32};
use sha3::Shake256;

use crate::{BbsError, BbsResult, params::Ciphersuite};

/// Spec 1.5.4; RFC 9380 Sections 5.3.1–5.3.3. Expand with the selected suite.
///
/// The SHAKE-256 suite targets k = 128, so oversized DSTs are hashed to 32
/// octets. The expander bounds are checked here before invoking the crate,
/// whose public expansion API otherwise panics on excessive output lengths.
pub fn expand_message(
    suite: Ciphersuite,
    msg: &[u8],
    dst: &[u8],
    len: usize,
) -> BbsResult<Vec<u8>> {
    if len > 65535 {
        return Err(BbsError::Abort(
            "expand_message output exceeds 65535 octets",
        ));
    }
    match suite {
        Ciphersuite::Sha256 => {
            if len.div_ceil(32) > 255 {
                return Err(BbsError::Abort("expand_message_xmd ell exceeds 255"));
            }
            Ok(ExpandMsgXmd::<Sha256>::init_expand::<_, U32>([msg], dst, len).into_vec())
        }
        Ciphersuite::Shake256 => {
            Ok(ExpandMsgXof::<Shake256>::init_expand::<_, U32>([msg], dst, len).into_vec())
        }
    }
}

/// Spec 1.5.4; RFC 9380 Section 8.8.1; BBS-12 Appendix A.1. Hash to G1.
///
/// The random-oracle construction maps two 64-octet field elements with SSWU,
/// adds the resulting points, and clears the cofactor. The curve crate uses
/// k = 128 for G1 with either expander, including oversized DST handling.
pub fn hash_to_curve_g1(suite: Ciphersuite, msg: &[u8], dst: &[u8]) -> BbsResult<G1Projective> {
    Ok(match suite {
        Ciphersuite::Sha256 => {
            <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve([msg], dst)
        }
        Ciphersuite::Shake256 => {
            <G1Projective as HashToCurve<ExpandMsgXof<Shake256>>>::hash_to_curve([msg], dst)
        }
    })
}

/// Spec 4.2.4.6 decode_G1. Check decoding, subgroup, identity, then encoding.
pub fn decode_G1(octets: &[u8], allow_identity: bool) -> BbsResult<G1Projective> {
    let bytes: &[u8; 48] = octets.try_into().map_err(|_| BbsError::Invalid)?;
    // The unchecked decoder recovers y and validates compressed coordinate
    // syntax. Check curve membership explicitly before testing the subgroup.
    let X = Option::<G1Affine>::from(G1Affine::from_compressed_unchecked(bytes))
        .ok_or(BbsError::Invalid)?;
    if !bool::from(X.is_on_curve()) {
        return Err(BbsError::Invalid);
    }
    if !bool::from(X.is_torsion_free()) {
        return Err(BbsError::Invalid);
    }
    if !allow_identity && bool::from(X.is_identity()) {
        return Err(BbsError::Invalid);
    }
    if X.to_compressed() != *bytes {
        return Err(BbsError::Invalid);
    }
    Ok(G1Projective::from(X))
}

/// Spec 4.2.4.6 octets_to_pubkey. Decode a canonical nonidentity G2 point.
pub fn octets_to_pubkey(PK: &[u8]) -> BbsResult<G2Projective> {
    let bytes: &[u8; 96] = PK.try_into().map_err(|_| BbsError::Invalid)?;
    let W = Option::<G2Affine>::from(G2Affine::from_compressed_unchecked(bytes))
        .ok_or(BbsError::Invalid)?;
    if !bool::from(W.is_on_curve()) {
        return Err(BbsError::Invalid);
    }
    if !bool::from(W.is_torsion_free()) {
        return Err(BbsError::Invalid);
    }
    if bool::from(W.is_identity()) {
        return Err(BbsError::Invalid);
    }
    if W.to_compressed() != *bytes {
        return Err(BbsError::Invalid);
    }
    Ok(G2Projective::from(W))
}

/// Spec 1.5.5 point_to_octets_E1; BBS-12 Appendix B.2. Compress a G1 point.
pub fn point_to_octets_E1(point: &G1Projective) -> [u8; 48] {
    G1Affine::from(point).to_compressed()
}

/// Spec 1.5.5 point_to_octets_E2; BBS-12 Appendix B.2. Compress a G2 point.
pub fn point_to_octets_E2(point: &G2Projective) -> [u8; 96] {
    G2Affine::from(point).to_compressed()
}

/// Spec 4.2.4.1. Encode a scalar as exactly 32 big-endian octets.
pub fn scalar_to_octets(scalar: &Scalar) -> [u8; 32] {
    let mut bytes = scalar.to_bytes();
    bytes.reverse();
    bytes
}

/// Spec 1.4.3 and 4.2.4. Decode a canonical scalar, permitting zero.
///
/// This conversion never reduces an out-of-range input. Procedures that
/// require nonzero scalars perform that separate check themselves.
pub fn scalar_from_octets(octets: &[u8]) -> BbsResult<Scalar> {
    let mut bytes: [u8; 32] = octets.try_into().map_err(|_| BbsError::Invalid)?;
    bytes.reverse();
    Option::<Scalar>::from(Scalar::from_bytes(&bytes)).ok_or(BbsError::Invalid)
}

/// Spec 4.2.1–4.2.2. Reduce 48 big-endian hash/random octets modulo r.
///
/// Only explicitly reducing procedures use this function; external scalar
/// inputs must use scalar_from_octets instead.
pub fn scalar_from_wide(octets: &[u8; 48]) -> Scalar {
    let mut wide = [0u8; 64];
    for (i, byte) in octets.iter().rev().enumerate() {
        wide[i] = *byte;
    }
    Scalar::from_bytes_wide(&wide)
}

/// Spec 1.4.2; RFC 8017 Section 4.2. An arbitrary-width non-negative integer.
///
/// The private representation is big-endian with no leading zero octets;
/// zero has an empty representation. Equality compares numeric values, so
/// OS2IP inputs that differ only in leading zeros produce equal integers.
/// This type provides lossless encoding and checked bounded conversion, not
/// scalar arithmetic or reduction modulo the curve order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct UnsignedInteger {
    bytes: Vec<u8>,
}

impl UnsignedInteger {
    /// Spec 1.4.2. Borrow the minimal big-endian encoding; zero is empty.
    pub fn as_be_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Spec 1.4.2. Return the exact u128 value, or None when it does not fit.
    pub fn to_u128(&self) -> Option<u128> {
        if self.bytes.len() > 16 {
            return None;
        }
        Some(
            self.bytes
                .iter()
                .fold(0u128, |value, byte| (value << 8) | u128::from(*byte)),
        )
    }

    /// Spec 1.4.2; RFC 8017 Section 4.1 I2OSP for arbitrary-width integers.
    ///
    /// Encode exactly n octets, padding on the left with zeros. Abort when
    /// the integer does not fit or the output capacity cannot be allocated.
    pub fn to_octets(&self, n: usize) -> BbsResult<Vec<u8>> {
        integer_to_octets(&self.bytes, n)
    }
}

/// Spec 1.4.2; RFC 8017 Section 4.1. Encode big-endian integer bytes.
fn integer_to_octets(bytes: &[u8], n: usize) -> BbsResult<Vec<u8>> {
    let first_nonzero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    let bytes = &bytes[first_nonzero..];
    if bytes.len() > n {
        return Err(BbsError::Abort("I2OSP integer too large"));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(n)
        .map_err(|_| BbsError::Abort("I2OSP output length exceeds capacity"))?;
    output.resize(n, 0);
    output[n - bytes.len()..].copy_from_slice(bytes);
    Ok(output)
}

/// Spec 1.4.2; RFC 8017 Section 4.1 I2OSP. Encode a u128 unsigned integer.
///
/// For wider integers returned by OS2IP, use UnsignedInteger::to_octets.
pub fn I2OSP(x: u128, n: usize) -> BbsResult<Vec<u8>> {
    integer_to_octets(&x.to_be_bytes(), n)
}

/// Spec 1.4.2; RFC 8017 Section 4.2 OS2IP. Decode an unsigned integer.
///
/// Accept any input width, preserving the full value without reduction.
/// Leading zeros are discarded; an empty or all-zero input represents zero.
/// Failure is possible only when capacity for the integer cannot be allocated.
/// Scalar decoding and hash reduction use their dedicated helpers.
pub fn OS2IP(octets: &[u8]) -> BbsResult<UnsignedInteger> {
    let first_nonzero = octets
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(octets.len());
    let octets = &octets[first_nonzero..];
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(octets.len())
        .map_err(|_| BbsError::Abort("OS2IP integer length exceeds capacity"))?;
    bytes.extend_from_slice(octets);
    Ok(UnsignedInteger { bytes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    /// Spec 1.4.3. Decode test constants written as big-endian hexadecimal.
    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    /// RFC 9380 Section 5.3.3; BBS-12 Appendix A.1. Oversized DSTs use k128.
    #[test]
    fn oversized_dst_reduction() {
        let dst = [0x42; 256];
        let mut sha256 = Sha256::new();
        Digest::update(&mut sha256, b"H2C-OVERSIZE-DST-");
        Digest::update(&mut sha256, dst);
        let reduced_xmd = sha256.finalize();
        assert_eq!(
            expand_message(Ciphersuite::Sha256, b"msg", &dst, 64).unwrap(),
            expand_message(Ciphersuite::Sha256, b"msg", &reduced_xmd, 64).unwrap()
        );
        let mut shake256 = Shake256::default();
        Update::update(&mut shake256, b"H2C-OVERSIZE-DST-");
        Update::update(&mut shake256, &dst);
        let mut reduced_xof = [0; 32];
        shake256.finalize_xof().read(&mut reduced_xof);
        assert_eq!(
            expand_message(Ciphersuite::Shake256, b"msg", &dst, 64).unwrap(),
            expand_message(Ciphersuite::Shake256, b"msg", &reduced_xof, 64).unwrap()
        );
    }

    /// RFC 9380 Sections 5.3.1–5.3.2. Exercise expansion limits without panics.
    #[test]
    fn expansion_bounds() {
        assert!(expand_message(Ciphersuite::Sha256, b"", b"", 8160).is_ok());
        assert!(matches!(
            expand_message(Ciphersuite::Sha256, b"", b"", 8161),
            Err(BbsError::Abort(_))
        ));
        assert!(expand_message(Ciphersuite::Shake256, b"", b"", 65535).is_ok());
        assert!(matches!(
            expand_message(Ciphersuite::Shake256, b"", b"", 65536),
            Err(BbsError::Abort(_))
        ));
        assert!(
            expand_message(Ciphersuite::Sha256, b"", b"", 0)
                .unwrap()
                .is_empty()
        );
    }

    /// Spec 4.2.4.6. Reject malformed, noncanonical, identity and torsion points.
    #[test]
    fn point_decoding_checks() {
        let g1 = G1Projective::generator();
        assert_eq!(decode_G1(&point_to_octets_E1(&g1), false).unwrap(), g1);
        let identity = point_to_octets_E1(&G1Projective::identity());
        assert!(decode_G1(&identity, false).is_err());
        assert_eq!(
            decode_G1(&identity, true).unwrap(),
            G1Projective::identity()
        );
        let mut noncanonical = identity;
        noncanonical[47] = 1;
        assert!(decode_G1(&noncanonical, true).is_err());
        assert!(decode_G1(&[0; 47], true).is_err());
        assert!(decode_G1(&[0xff; 48], true).is_err());
        // x = 0, y = 2 is on E1, has order 3, and must fail the subgroup check.
        let mut torsion = [0; 48];
        torsion[0] = 0x80;
        assert!(bool::from(
            G1Affine::from_compressed_unchecked(&torsion).is_some()
        ));
        assert!(decode_G1(&torsion, true).is_err());
        let g2 = G2Projective::generator();
        assert_eq!(octets_to_pubkey(&point_to_octets_E2(&g2)).unwrap(), g2);
        assert!(octets_to_pubkey(&point_to_octets_E2(&G2Projective::identity())).is_err());
        assert!(octets_to_pubkey(&[0xff; 96]).is_err());
        assert!(octets_to_pubkey(&[0; 95]).is_err());
        // Find an ordinary E2 point before cofactor clearing; its nontrivial
        // cofactor component must be rejected by the explicit subgroup check.
        let mut found_non_subgroup = false;
        for x in 0..=255u8 {
            let mut encoded = [0; 96];
            encoded[0] = 0x80;
            encoded[95] = x;
            if let Some(point) =
                Option::<G2Affine>::from(G2Affine::from_compressed_unchecked(&encoded))
            {
                if !bool::from(point.is_torsion_free()) {
                    assert!(octets_to_pubkey(&encoded).is_err());
                    found_non_subgroup = true;
                    break;
                }
            }
        }
        assert!(found_non_subgroup);
    }

    /// Spec 1.4.3, 4.2.1–4.2.2. Distinguish scalar decoding from reduction.
    #[test]
    fn scalar_encoding_and_reduction() {
        let mut one = [0; 32];
        one[31] = 1;
        assert_eq!(scalar_from_octets(&one).unwrap(), Scalar::one());
        assert_eq!(scalar_to_octets(&Scalar::one()), one);
        assert_eq!(scalar_from_octets(&[0; 32]).unwrap(), Scalar::zero());
        let modulus = hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
        assert!(scalar_from_octets(&modulus).is_err());
        assert!(scalar_from_octets(&[0xff; 32]).is_err());
        let mut wide = [0; 48];
        wide[16..].copy_from_slice(&modulus);
        assert_eq!(scalar_from_wide(&wide), Scalar::zero());
        wide[47] += 1;
        assert_eq!(scalar_from_wide(&wide), Scalar::one());
    }

    /// RFC 8017 Sections 4.1–4.2. Bounded integer encoding and conversion.
    #[test]
    fn integer_conversions() {
        assert_eq!(I2OSP(0x123, 3).unwrap(), [0, 1, 0x23]);
        assert_eq!(OS2IP(&[0, 1, 0x23]).unwrap().to_u128(), Some(0x123));
        assert!(I2OSP(0, 0).unwrap().is_empty());
        assert!(I2OSP(1, 0).is_err());
        assert!(I2OSP(256, 1).is_err());
        assert_eq!(
            OS2IP(&I2OSP(u128::MAX, 17).unwrap()).unwrap().to_u128(),
            Some(u128::MAX)
        );
        assert!(matches!(I2OSP(0, usize::MAX), Err(BbsError::Abort(_))));
    }

    /// RFC 8017 Section 4.2. Zero and leading zeros have one representation.
    #[test]
    fn integer_canonicalization() {
        let zero = OS2IP(&[]).unwrap();
        assert_eq!(zero, OS2IP(&[0; 64]).unwrap());
        assert_eq!(zero, UnsignedInteger::default());
        assert!(zero.as_be_bytes().is_empty());
        assert_eq!(zero.to_u128(), Some(0));
        assert!(zero.to_octets(0).unwrap().is_empty());
        assert_eq!(zero.to_octets(3).unwrap(), [0, 0, 0]);

        let value = OS2IP(&[0, 0, 0x12, 0x34, 0]).unwrap();
        assert_eq!(value, OS2IP(&[0x12, 0x34, 0]).unwrap());
        assert_eq!(value.as_be_bytes(), [0x12, 0x34, 0]);
        assert_eq!(value.to_u128(), Some(0x123400));
        assert_eq!(value.to_octets(5).unwrap(), [0, 0, 0x12, 0x34, 0]);
    }

    /// RFC 8017 Sections 4.1–4.2. Preserve 2^128 and wider protocol-sized values.
    #[test]
    fn integer_arbitrary_width_roundtrips() {
        let mut two_to_128 = [0; 17];
        two_to_128[0] = 1;
        let value = OS2IP(&two_to_128).unwrap();
        assert_eq!(value.as_be_bytes(), two_to_128);
        assert_eq!(value.to_u128(), None);
        assert_eq!(value.to_octets(17).unwrap(), two_to_128);
        assert!(matches!(value.to_octets(16), Err(BbsError::Abort(_))));
        let padded = [vec![0; 20], two_to_128.to_vec()].concat();
        assert_eq!(OS2IP(&padded).unwrap(), value);
        assert_eq!(value.to_octets(padded.len()).unwrap(), padded);

        for length in [32, 48, 1024] {
            let mut bytes: Vec<u8> = (0..length).map(|i| (i % 256) as u8).collect();
            bytes[0] = 0x80;
            let value = OS2IP(&bytes).unwrap();
            assert_eq!(value.as_be_bytes(), bytes);
            assert_eq!(value.to_u128(), None);
            assert_eq!(value.to_octets(length).unwrap(), bytes);
            assert!(matches!(
                value.to_octets(length - 1),
                Err(BbsError::Abort(_))
            ));
            let padded = [vec![0; 2], bytes].concat();
            assert_eq!(value.to_octets(length + 2).unwrap(), padded);
            assert_eq!(OS2IP(&padded).unwrap(), value);
        }
    }
}
