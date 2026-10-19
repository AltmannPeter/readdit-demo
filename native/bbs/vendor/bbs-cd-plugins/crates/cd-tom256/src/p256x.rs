//! P-256 helpers (RustCrypto `p256`): canonical SEC1 encoding, coordinates,
//! limbs and conversions to the Tom scalar field.
#![allow(deprecated)] // generic-array 0.14 accessors used by p256 0.13
use p256::elliptic_curve::{
    ops::Reduce,
    point::AffineCoordinates,
    sec1::{FromEncodedPoint, ToEncodedPoint},
    PrimeField,
};
use p256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar, U256};

use crate::tom::{fr_from_be, Fr};
use bbs_cd_plugin::error::{decode, Result};

/// SEC1 compressed encoding (33 bytes).  Panics on the identity (prover bug).
pub fn encode(p: &ProjectivePoint) -> [u8; 33] {
    let e = p.to_affine().to_encoded_point(true);
    e.as_bytes().try_into().expect("non-identity compressed point")
}

/// Strict decoding: 33 bytes, prefix 02/03, x < p, on curve, non-identity.
pub fn decode_point(b: &[u8]) -> Result<ProjectivePoint> {
    if b.len() != 33 || (b[0] != 2 && b[0] != 3) {
        return decode("P-256 point encoding");
    }
    let ep = EncodedPoint::from_bytes(b).map_err(|_| bbs_cd_plugin::Error::Decode("P-256 point".into()))?;
    let a: Option<AffinePoint> = AffinePoint::from_encoded_point(&ep).into();
    match a {
        Some(a) => Ok(ProjectivePoint::from(a)),
        None => decode("P-256 point not on curve / non-canonical"),
    }
}

/// Affine coordinates (x, y) as 32-byte big-endian strings.
pub fn coords(p: &ProjectivePoint) -> ([u8; 32], [u8; 32]) {
    let e = p.to_affine().to_encoded_point(false);
    let x: [u8; 32] = e.x().expect("non-identity").as_slice().try_into().unwrap();
    let y: [u8; 32] = e.y().expect("non-identity").as_slice().try_into().unwrap();
    (x, y)
}

pub fn x_coord(p: &ProjectivePoint) -> [u8; 32] {
    p.to_affine().x().into()
}

/// Coordinates as Tom scalars (mod p, exact because coordinates are < p).
pub fn coords_fr(p: &ProjectivePoint) -> (Fr, Fr) {
    let (x, y) = coords(p);
    (fr_from_be(&x), fr_from_be(&y))
}

/// Split a 256-bit big-endian value into k little-endian limbs of `limb_bits`.
pub fn split_limbs(v: &[u8; 32], limb_bits: u8) -> Vec<u128> {
    let k = crate::config::limbs_per_coord(limb_bits);
    let mut x = num_bigint::BigUint::from_bytes_be(v);
    let mask = (num_bigint::BigUint::from(1u8) << limb_bits as u32) - 1u32;
    (0..k)
        .map(|_| {
            let limb = &x & &mask;
            x >>= limb_bits as u32;
            let b = limb.to_bytes_le();
            let mut a = [0u8; 16];
            a[..b.len()].copy_from_slice(&b);
            u128::from_le_bytes(a)
        })
        .collect()
}

/// Key limbs: the x limbs then the y limbs, each little-endian.
pub fn limbs(p: &ProjectivePoint, limb_bits: u8) -> Vec<u128> {
    let (x, y) = coords(p);
    limbs_of_coords(&x, &y, limb_bits)
}

/// Limbs of an arbitrary coordinate pair given as big-endian bytes.
pub fn limbs_of_coords(x: &[u8; 32], y: &[u8; 32], limb_bits: u8) -> Vec<u128> {
    let mut l = split_limbs(x, limb_bits);
    l.extend(split_limbs(y, limb_bits));
    l
}

/// h = OS2IP(digest) mod n.
pub fn scalar_reduce(digest: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(digest))
}

pub fn scalar_to_be(s: &Scalar) -> [u8; 32] {
    s.to_repr().into()
}

/// Canonical scalar parse: value < n (zero allowed here; callers check).
pub fn scalar_from_canonical(b: &[u8; 32]) -> Result<Scalar> {
    let s: Option<Scalar> = Scalar::from_repr(*FieldBytes::from_slice(b)).into();
    s.ok_or_else(|| bbs_cd_plugin::Error::Decode("P-256 scalar >= n".into()))
}

/// (n - 1) / 2 as a scalar, for the low-s rule.
pub fn half_n_be() -> [u8; 32] {
    // n = ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    let n = num_bigint::BigUint::parse_bytes(b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
        .unwrap();
    let h: num_bigint::BigUint = (n - 1u32) >> 1usize;
    let v = h.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(&v);
    out
}

pub fn is_high_s(s: &Scalar) -> bool {
    scalar_to_be(s) > half_n_be()
}

/// Inverse of [`limbs`]: the point whose coordinates have these limbs.
/// Rejects limbs ≥ 2^limb_bits, coordinates ≥ 2^256 (or ≥ p) and points
/// that are not on the curve.
pub fn point_from_limbs(limbs: &[u128], limb_bits: u8) -> Result<ProjectivePoint> {
    let k = crate::config::limbs_per_coord(limb_bits);
    if limbs.len() != 2 * k {
        return decode("P-256 limb count");
    }
    if limb_bits < 128 && limbs.iter().any(|&l| l >> limb_bits != 0) {
        return decode("P-256 limb out of range");
    }
    let join = |ls: &[u128]| -> Result<[u8; 32]> {
        let mut v = num_bigint::BigUint::default();
        for (i, &l) in ls.iter().enumerate() {
            v += num_bigint::BigUint::from(l) << (limb_bits as usize * i);
        }
        let b = v.to_bytes_be();
        if b.len() > 32 {
            return decode("P-256 coordinate ≥ 2^256");
        }
        let mut out = [0u8; 32];
        out[32 - b.len()..].copy_from_slice(&b);
        Ok(out)
    };
    let (x, y) = (join(&limbs[..k])?, join(&limbs[k..])?);
    let ep = EncodedPoint::from_affine_coordinates(&FieldBytes::from(x), &FieldBytes::from(y), false);
    let a: Option<AffinePoint> = AffinePoint::from_encoded_point(&ep).into();
    match a {
        Some(a) => Ok(ProjectivePoint::from(a)),
        None => decode("P-256 limbs do not encode a curve point"),
    }
}
