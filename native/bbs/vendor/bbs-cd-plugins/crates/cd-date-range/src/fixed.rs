//! Precomputed tables for the two fixed generators Y0 and Y1.
//!
//! For a base P, window j (0 ≤ j < 32) and byte value b (1 ≤ b ≤ 255) the
//! table holds b·256^j·P in affine form.  a·P is then the sum, over the 32
//! bytes of a's canonical little-endian encoding, of one table entry per
//! nonzero byte: at most 32 additions and no doublings, against about 255
//! doublings for a variable-base multiplication.
//!
//! * Exact for every scalar: only the curve library's complete mixed
//!   addition (projective + affine) is used, zero bytes are skipped, and no
//!   table entry is the identity (P has prime order r > 2^255).
//! * The tables depend only on the public generators of the ciphersuite.
//!   They are built once per process on first use (2 × 8,160 points,
//!   about 1.5 MB) and never change, like the generator cache of the core;
//!   nothing about a proof or a holder is kept between calls.
//! * Variable-time, like the rest of the holder and verifier paths.
use std::sync::OnceLock;

use bbs_cd::utils::commitment_generators;
use bbs_cd_plugin::issuer::SUITE;
use bls12_381::{G1Affine, G1Projective, Scalar};

const WINDOWS: usize = 32;
const ENTRIES: usize = 255;

/// Fixed-base table of one point.
pub struct FixedBase {
    point: G1Projective,
    /// Entry (j, b) at index j·255 + (b − 1).
    table: Vec<G1Affine>,
}

impl FixedBase {
    pub fn new(p: &G1Projective) -> FixedBase {
        let mut proj = Vec::with_capacity(WINDOWS * ENTRIES);
        let mut base = *p; // 256^j·P
        for _ in 0..WINDOWS {
            let mut acc = base;
            proj.push(acc);
            for _ in 1..ENTRIES {
                acc += base;
                proj.push(acc);
            }
            for _ in 0..8 {
                base = base.double();
            }
        }
        let mut table = vec![G1Affine::identity(); proj.len()];
        G1Projective::batch_normalize(&proj, &mut table);
        FixedBase { point: *p, table }
    }

    /// The base point.
    pub fn point(&self) -> G1Projective {
        self.point
    }

    /// a·P.
    pub fn mul(&self, a: &Scalar) -> G1Projective {
        let mut acc = G1Projective::identity();
        for (j, &b) in a.to_bytes().iter().enumerate() {
            if b != 0 {
                acc += &self.table[j * ENTRIES + (b as usize - 1)];
            }
        }
        acc
    }
}

/// The ETSI commitment generators with their tables.
pub struct Generators {
    pub y0: FixedBase,
    pub y1: FixedBase,
}

impl Generators {
    /// a·Y0 + b·Y1.
    pub fn commit(&self, a: &Scalar, b: &Scalar) -> G1Projective {
        self.y0.mul(a) + self.y1.mul(b)
    }
}

static GENERATORS: OnceLock<Generators> = OnceLock::new();

/// Tables for Y0 and Y1 of the suite (built on first use).
pub fn generators() -> &'static Generators {
    GENERATORS.get_or_init(|| {
        let (y0, y1) = commitment_generators(SUITE, &SUITE.api_id()).expect("commitment generators");
        Generators { y0: FixedBase::new(&y0), y1: FixedBase::new(&y1) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    fn rand_scalar() -> Scalar {
        let mut w = [0u8; 64];
        OsRng.fill_bytes(&mut w);
        Scalar::from_bytes_wide(&w)
    }

    #[test]
    fn table_multiplication_is_exact() {
        let g = generators();
        let mut scalars = vec![
            Scalar::zero(),
            Scalar::one(),
            -Scalar::one(),
            Scalar::from(255u64),
            Scalar::from(256u64),
            Scalar::from(u64::MAX),
            -Scalar::from(2u64),
        ];
        // every single-byte value in the lowest and the highest window
        for b in 1..=255u8 {
            let mut x = [0u8; 32];
            x[0] = b;
            scalars.push(Scalar::from_bytes(&x).unwrap());
            x[0] = 0;
            x[31] = b & 0x73; // stays below r
            if let Some(s) = Option::<Scalar>::from(Scalar::from_bytes(&x)) {
                scalars.push(s);
            }
        }
        scalars.extend((0..64).map(|_| rand_scalar()));
        for p in [&g.y0, &g.y1] {
            for s in &scalars {
                assert_eq!(p.mul(s), p.point() * s);
            }
        }
        let (a, b) = (rand_scalar(), rand_scalar());
        assert_eq!(g.commit(&a, &b), g.y0.point() * a + g.y1.point() * b);
    }

    #[test]
    fn tables_are_for_the_etsi_generators() {
        let (y0, y1) = commitment_generators(SUITE, &SUITE.api_id()).unwrap();
        assert_eq!(generators().y0.point(), y0);
        assert_eq!(generators().y1.point(), y1);
    }
}
