//! Range proof for a Pedersen commitment C′ = v·Y0 + s·Y1 with v ∈ [0, N]
//! (docs/plugins/DATE-RANGE.md §3): bit decomposition over the bases of the
//! Privacy Pass range proof for arbitrary values, one Schnorr bit proof per
//! digit, one challenge for all of them.
//!
//! Generic over N; the date plugin supplies C′, N and the challenge function.
//! Multiples of Y0 and Y1 use the precomputed tables of [`crate::fixed`];
//! multiples of the per-proof points D_i use wNAF; points are encoded for
//! the challenge in one batch; the sum check uses Horner's rule.
use bbs_cd::helpers::mul_vartime;
use bbs_cd::primitives::{decode_G1, scalar_from_octets, scalar_from_wide, scalar_to_octets};
use bbs_cd_plugin::codec::Reader;
use bbs_cd_plugin::error::{Error, Result};
use bbs_cd_plugin::plugin::CryptoRngCore;
use bls12_381::{G1Affine, G1Projective, Scalar};

use crate::fixed::generators;

/// Proof magic.
pub const MAGIC: &[u8; 4] = b"DRP\x01";
/// Bytes per digit: D_i ‖ z_b ‖ z_s ‖ z_t.
pub const DIGIT_LEN: usize = 48 + 3 * 32;

/// Proof length for k digits.
pub fn proof_len(k: usize) -> usize {
    4 + 32 + DIGIT_LEN * k
}

/// The bases β_0 … β_{k−1} for the limit N ≥ 1: powers of two and a last
/// base that makes the largest combination exactly N.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bases {
    pub n: u64,
    pub beta: Vec<u64>,
}

impl Bases {
    pub fn new(n: u64) -> Bases {
        assert!(n >= 1, "range limit N must be at least 1");
        let k = 64 - n.leading_zeros() as usize;
        let mut beta: Vec<u64> = (0..k - 1).map(|i| 1u64 << i).collect();
        beta.push(n - (1u64 << (k - 1)) + 1);
        Bases { n, beta }
    }

    pub fn k(&self) -> usize {
        self.beta.len()
    }

    /// Digits of v ∈ [0, N]; `None` outside the range.
    pub fn digits(&self, v: u64) -> Option<Vec<u64>> {
        if v > self.n {
            return None;
        }
        let k = self.k();
        let half = 1u64 << (k - 1);
        let (last, rest) = if v < half { (0, v) } else { (1, v - self.beta[k - 1]) };
        let mut d: Vec<u64> = (0..k - 1).map(|i| (rest >> i) & 1).collect();
        d.push(last);
        debug_assert_eq!(d.iter().zip(&self.beta).map(|(a, b)| a * b).sum::<u64>(), v);
        Some(d)
    }

    fn beta_scalars(&self) -> Vec<Scalar> {
        self.beta.iter().map(|&b| Scalar::from(b)).collect()
    }
}

/// Public statement: the commitment C′ to v (with respect to the ETSI
/// generators Y0, Y1 of [`crate::fixed::generators`]).
#[derive(Clone, Copy, Debug)]
pub struct Statement {
    pub c_prime: G1Projective,
}

/// The values the challenge is computed from: the encodings of D_i, A_i and
/// B_i, each concatenated in digit order.
pub struct ChallengeInput<'a> {
    pub d: &'a [u8],
    pub a: &'a [u8],
    pub b: &'a [u8],
}

pub(crate) fn rand_scalar(rng: &mut dyn CryptoRngCore) -> Scalar {
    let mut w = [0u8; 48];
    rng.fill_bytes(&mut w);
    scalar_from_wide(&w)
}

/// Compressed encodings of `points`, concatenated.  One field inversion for
/// all of them (Montgomery's trick, `batch_normalize`) instead of one per
/// point; the bytes are those of `point_to_octets_E1` (affine form is unique).
pub(crate) fn encode_points(points: &[G1Projective]) -> Vec<u8> {
    let mut affine = vec![G1Affine::identity(); points.len()];
    G1Projective::batch_normalize(points, &mut affine);
    affine.iter().flat_map(|p| p.to_compressed()).collect()
}

/// n·P for a small integer n, by double-and-add from the top bit (complete
/// projective formulas only).
fn mul_u64(p: &G1Projective, n: u64) -> G1Projective {
    let mut acc = G1Projective::identity();
    for i in (0..64 - n.leading_zeros()).rev() {
        acc = acc.double();
        if (n >> i) & 1 == 1 {
            acc += p;
        }
    }
    acc
}

/// Σ β_i·D_i.  β_i = 2^i for i < k − 1, so that part is Horner's rule (one
/// doubling and one addition per digit); the last base is a small integer.
pub(crate) fn weighted_sum(points: &[G1Projective], bases: &Bases) -> G1Projective {
    let k = bases.k();
    assert_eq!(points.len(), k, "one point per base");
    let mut acc = G1Projective::identity();
    for p in points[..k - 1].iter().rev() {
        acc = acc.double() + p;
    }
    acc + mul_u64(&points[k - 1], bases.beta[k - 1])
}

/// Honest proof that C′ commits to v ∈ [0, N] with opening s.
pub fn prove(
    st: &Statement,
    bases: &Bases,
    v: u64,
    s: Scalar,
    challenge: &dyn Fn(&ChallengeInput) -> Result<Scalar>,
    rng: &mut dyn CryptoRngCore,
) -> Result<Vec<u8>> {
    let d = bases.digits(v).ok_or_else(|| Error::Prover("value outside the range".into()))?;
    debug_assert_eq!(generators().commit(&Scalar::from(v), &s), st.c_prime, "C′ = v·Y0 + s·Y1");
    let digits: Vec<Scalar> = d.into_iter().map(Scalar::from).collect();
    prove_digits(bases, &digits, s, challenge, rng)
}

/// The proof for arbitrary digits (scalars) and opening s.  Sound inputs are
/// digits in {0, 1} whose combination is v; anything else gives a proof the
/// verifier rejects.  Used by `prove` and, through `insecure_test_controls`,
/// by the attack tests.  The openings make Σ β_i·D_i = (Σ β_i·d_i)·Y0 + s·Y1,
/// so C′ itself is not needed.
pub(crate) fn prove_digits(
    bases: &Bases,
    digits: &[Scalar],
    s: Scalar,
    challenge: &dyn Fn(&ChallengeInput) -> Result<Scalar>,
    rng: &mut dyn CryptoRngCore,
) -> Result<Vec<u8>> {
    let k = bases.k();
    assert_eq!(digits.len(), k, "one digit per base");
    let beta = bases.beta_scalars();
    // Openings: random, the last one makes Σ β_i·D_i = C′ exact.
    let mut si: Vec<Scalar> = (0..k - 1).map(|_| rand_scalar(rng)).collect();
    let partial: Scalar = si.iter().zip(&beta).map(|(a, b)| a * b).sum();
    let inv = Option::<Scalar>::from(beta[k - 1].invert()).expect("nonzero base");
    si.push((s - partial) * inv);
    let g = generators();
    let mut dp = Vec::with_capacity(k);
    let mut ap = Vec::with_capacity(k);
    let mut bp = Vec::with_capacity(k);
    let mut nonces = Vec::with_capacity(k);
    for i in 0..k {
        let di = g.commit(&digits[i], &si[i]);
        let (rho, sigma, tau) = (rand_scalar(rng), rand_scalar(rng), rand_scalar(rng));
        ap.push(g.commit(&rho, &sigma));
        bp.push(mul_vartime(&di, &rho) + g.y1.mul(&tau));
        dp.push(di);
        nonces.push((rho, sigma, tau));
    }
    let (db, ab, bb) = (encode_points(&dp), encode_points(&ap), encode_points(&bp));
    let c = challenge(&ChallengeInput { d: &db, a: &ab, b: &bb })?;
    let mut out = Vec::with_capacity(proof_len(k));
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&scalar_to_octets(&c));
    for i in 0..k {
        let (rho, sigma, tau) = nonces[i];
        let t = (Scalar::one() - digits[i]) * si[i];
        out.extend_from_slice(&db[48 * i..48 * (i + 1)]);
        out.extend_from_slice(&scalar_to_octets(&(rho + c * digits[i])));
        out.extend_from_slice(&scalar_to_octets(&(sigma + c * si[i])));
        out.extend_from_slice(&scalar_to_octets(&(tau + c * t)));
    }
    debug_assert_eq!(out.len(), proof_len(k));
    Ok(out)
}

/// Verify a range proof (docs/plugins/DATE-RANGE.md §5–§6).
pub fn verify(
    st: &Statement,
    bases: &Bases,
    proof: &[u8],
    challenge: &dyn Fn(&ChallengeInput) -> Result<Scalar>,
) -> Result<()> {
    let k = bases.k();
    let rej = |s: &str| Error::Reject(format!("date-range: {s}"));
    if proof.len() != proof_len(k) {
        return Err(Error::Decode("date-range: proof length".into()));
    }
    let mut r = Reader::new(proof, proof_len(k))?;
    if r.take(4)? != MAGIC {
        return Err(Error::Decode("date-range: magic".into()));
    }
    let sc = |b: &[u8]| scalar_from_octets(b).map_err(|_| Error::Decode("date-range: scalar".into()));
    let c = sc(r.take(32)?)?;
    let mut dp = Vec::with_capacity(k);
    let mut z = Vec::with_capacity(k);
    let mut db = Vec::with_capacity(48 * k);
    for _ in 0..k {
        let enc = r.take(48)?;
        dp.push(decode_G1(enc, true).map_err(|_| Error::Decode("date-range: point".into()))?);
        db.extend_from_slice(enc);
        z.push((sc(r.take(32)?)?, sc(r.take(32)?)?, sc(r.take(32)?)?));
    }
    r.end()?;
    if weighted_sum(&dp, bases) != st.c_prime {
        return Err(rej("digit commitments do not sum to the committed value"));
    }
    let g = generators();
    let mut ap = Vec::with_capacity(k);
    let mut bp = Vec::with_capacity(k);
    for (di, (zb, zs, zt)) in dp.iter().zip(&z) {
        // A_i = z_b·Y0 + z_s·Y1 − c·D_i,  B_i = (z_b − c)·D_i + z_t·Y1
        ap.push(g.commit(zb, zs) - mul_vartime(di, &c));
        bp.push(mul_vartime(di, &(*zb - c)) + g.y1.mul(zt));
    }
    let c2 = challenge(&ChallengeInput { d: &db, a: &encode_points(&ap), b: &encode_points(&bp) })?;
    if c2 != c {
        return Err(rej("bit proofs"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bbs_cd::helpers::msm_vartime;
    use bbs_cd::primitives::point_to_octets_E1;
    use bbs_cd::utils::commitment_generators;
    use bbs_cd_plugin::issuer::SUITE;
    use rand_core::OsRng;

    /// Textbook verification with plain scalar multiplication (no tables, no
    /// wNAF, no MSM): an independent check of the optimized prover and verifier.
    fn reference_verify(
        c_prime: G1Projective,
        bases: &Bases,
        proof: &[u8],
        ch: &dyn Fn(&ChallengeInput) -> Result<Scalar>,
    ) -> bool {
        let (y0, y1) = commitment_generators(SUITE, &SUITE.api_id()).unwrap();
        let c = scalar_from_octets(&proof[4..36]).unwrap();
        let (mut db, mut ab, mut bb) = (vec![], vec![], vec![]);
        let mut sum = G1Projective::identity();
        for (i, rec) in proof[36..].chunks(DIGIT_LEN).enumerate() {
            let d = decode_G1(&rec[..48], true).unwrap();
            let zb = scalar_from_octets(&rec[48..80]).unwrap();
            let zs = scalar_from_octets(&rec[80..112]).unwrap();
            let zt = scalar_from_octets(&rec[112..144]).unwrap();
            sum += d * Scalar::from(bases.beta[i]);
            db.extend_from_slice(&rec[..48]);
            ab.extend_from_slice(&point_to_octets_E1(&(y0 * zb + y1 * zs - d * c)));
            bb.extend_from_slice(&point_to_octets_E1(&(d * (zb - c) + y1 * zt)));
        }
        sum == c_prime && ch(&ChallengeInput { d: &db, a: &ab, b: &bb }).unwrap() == c
    }

    #[test]
    fn batch_encoding_and_weighted_sum_are_exact() {
        let (y0, _) = commitment_generators(SUITE, &SUITE.api_id()).unwrap();
        let mut pts: Vec<G1Projective> = (0..33).map(|_| y0 * rand_scalar(&mut OsRng)).collect();
        pts[3] = G1Projective::identity();
        pts[7] = pts[6];
        pts[9] = -pts[8];
        let one_by_one: Vec<u8> = pts.iter().flat_map(point_to_octets_E1).collect();
        assert_eq!(encode_points(&pts), one_by_one);
        assert!(encode_points(&[]).is_empty());
        for n in [1u64, 2, 3, 6, 40_472, 93_202, (1 << 20) - 1, 1 << 20, u32::MAX as u64] {
            let b = Bases::new(n);
            let p = &pts[..b.k()];
            assert_eq!(weighted_sum(p, &b), msm_vartime(p, &b.beta_scalars()), "n = {n}");
        }
        assert_eq!(mul_u64(&y0, 0), G1Projective::identity());
        assert_eq!(mul_u64(&y0, u64::MAX), y0 * Scalar::from(u64::MAX));
    }

    #[test]
    fn optimized_paths_match_the_textbook_relations() {
        let (y0, y1) = commitment_generators(SUITE, &SUITE.api_id()).unwrap();
        let ch = |ci: &ChallengeInput| -> Result<Scalar> {
            let t = bbs_cd_plugin::transcript::Transcript::new(b"t").add(b"d", ci.d).add(b"a", ci.a).add(b"b", ci.b);
            let mut w = [0u8; 48];
            w[..32].copy_from_slice(&t.digest());
            Ok(scalar_from_wide(&w))
        };
        for n in [1u64, 2, 7, 40_472, 93_202] {
            let b = Bases::new(n);
            for v in [0, n / 2, n] {
                let s = rand_scalar(&mut OsRng);
                let c_prime = y0 * Scalar::from(v) + y1 * s;
                let p = prove(&Statement { c_prime }, &b, v, s, &ch, &mut OsRng).unwrap();
                assert!(reference_verify(c_prime, &b, &p, &ch), "n = {n}, v = {v}");
                verify(&Statement { c_prime }, &b, &p, &ch).unwrap();
                // a proof the textbook check rejects, the optimized one rejects too
                let mut bad = p.clone();
                bad[36 + 60] ^= 1;
                assert!(!reference_verify(c_prime, &b, &bad, &ch));
                assert!(verify(&Statement { c_prime }, &b, &bad, &ch).is_err());
            }
        }
    }
}
