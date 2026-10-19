//! Hashed mode (default).
//!
//! The device signs, with ordinary ECDSA-P256-SHA256,
//!   m = Tr(DST_MSG; pstmt, nv, nh)
//! where pstmt binds the envelope (every D_j, ctx), the plugin's position,
//! attribute and parameters, and the limb commitments T_j.  Let
//! h = SHA-256(m) mod n.  The holder reveals the signature's nonce point
//! K = s⁻¹(h·G + r·Q) (so r = x(K) mod n is public) and proves, for the
//! committed device key Q (the fold of the T_j):
//!
//!   W = z·K       (SM, 128 rounds, base K, scalar z = s/r, W committed as C_W)
//!   W = Q + Hpt   (one PA proof; Hpt = (h/r)·G is public)
//!
//! which is ECDSA verification s·K = h·G + r·Q with s = z·r.  The on-curve
//! proof shows Q is a curve point, so W is one and the SM argument applies.
//! Transfer, on-curve, link and SM challenges come from the digest M′.
use std::time::{Duration, Instant};

use bbs_cd_plugin::codec::{Reader, Writer};
use bbs_cd_plugin::error::{Error, Result};
use bbs_cd_plugin::par::Parallelism;
use bbs_cd_plugin::plugin::{CommittedInput, CommittedView, EnvContext};
use bbs_cd_plugin::transcript::{sha256, Transcript};
use cd_tom256::p256x;
use cd_tom256::pa::{self, pa_prepare, pa_verify};
use cd_tom256::params::SM_ROUNDS;
use cd_tom256::sm::{commit_point, encode_sm_first, sm_prepare_rounds_with, SmRound};
use cd_tom256::tom::{self, fr_from_canonical, fr_rand, fr_to_be, Fr, TomPoint};
use p256::elliptic_curve::Group as _;
use p256::{ProjectivePoint, Scalar};
use rand_core::{CryptoRng, RngCore};

use crate::common::*;
use crate::device::HashSigner;
use crate::params::*;
use crate::ProveStats;

/// Link section: C_W (2 points) ‖ PA announcements (10 points) ‖ PA responses (12).
pub const LINK_POINTS: usize = 2 + pa::N_ANN;
pub const LINK_BYTES: usize = LINK_POINTS * 33 + pa::N_RESP * 32;
/// Index of the PA's U1 inside the link points (must be non-identity).
pub const LINK_U1: usize = 2 + 7;

/// The message the device signs with hashed ECDSA.
pub fn device_message(pstmt: &[u8], nonce: &[u8], nh: &[u8; 32]) -> Vec<u8> {
    Transcript::new(DST_MSG).add(b"statement", pstmt).add(b"nv", nonce).add(b"nh", nh).into_bytes()
}

/// The ECDSA-P256-SHA256 message representative: SHA-256(m) mod n.
pub fn msg_hash(m: &[u8]) -> Scalar {
    p256x::scalar_reduce(&sha256(m))
}

/// r = x(K) mod n.
pub fn r_of(k: &ProjectivePoint) -> Scalar {
    p256x::scalar_reduce(&p256x::x_coord(k))
}

/// Binding digest M′ of the hashed mode.
pub fn binding_digest(
    m_digest: &[u8; 32],
    k33: &[u8; 33],
    tr_ann: &[u8],
    oc_first: &[u8],
    link_first: &[u8],
    sm_ann: &[u8],
) -> [u8; 32] {
    Transcript::new(DST_M_HASHED)
        .add(b"message_digest", m_digest)
        .add(b"K", k33)
        .add(b"transfer_announcements", tr_ann)
        .add(b"on_curve_first", oc_first)
        .add(b"link_first", link_first)
        .add(b"sm_first_messages", sm_ann)
        .digest()
}

pub fn link_challenge(m: &[u8; 32]) -> Result<Fr> {
    hash_to_fr(&Transcript::new(DST_LINK).add(b"M", m).into_bytes(), DST_LINK_H2F)
}

fn encode_link_first(pts: &[TomPoint; LINK_POINTS]) -> Vec<u8> {
    tom::encode_batch(pts, |i| i != LINK_U1).concat()
}

// ----------------------------------------------------------------- prepare
/// Offline state: everything that does not depend on the signature.
pub struct HashedSlot {
    pub link: KeyLink,
}

pub fn prepare<R: RngCore + CryptoRng>(
    input: &CommittedInput,
    params: &EcdsaParams,
    spare_sets: usize,
    par: Parallelism,
    rng: &mut R,
) -> Result<HashedSlot> {
    if params.mode != Mode::Hashed {
        return Err(Error::Prover("ecdsa-pop: params are not hashed mode".into()));
    }
    Ok(HashedSlot { link: prepare_link(input, params, spare_sets, par, rng)? })
}

// ------------------------------------------------------------------ prove
#[allow(clippy::too_many_arguments)]
pub fn prove<R: RngCore + CryptoRng>(
    slot: HashedSlot,
    env: &EnvContext,
    input: &CommittedInput,
    params: &[u8],
    signer: &dyn HashSigner,
    nh: Option<[u8; 32]>,
    par: Parallelism,
    rng: &mut R,
    stats: Option<&mut ProveStats>,
) -> Result<Vec<u8>> {
    let t0 = Instant::now();
    let link = slot.link;
    link.check_input(input, params)?;
    let q = link.q;
    if signer.hash_public_key()? != p256x::encode(&q) {
        return Err(Error::Prover("signing device does not match the committed device key".into()));
    }
    let pstmt = plugin_statement(env, &input.attribute.name, params, None, &link.t_bytes);
    let t1 = Instant::now();
    let mut sign_time = Duration::ZERO;
    let mut sign_attempts = 0;
    // Sign; retry with a fresh nh only in the negligible exceptional cases.
    let (nh, m, k, z, hpt, w, t_signed) = loop {
        let nh_ = match nh {
            Some(x) => x,
            None => {
                let mut b = [0u8; 32];
                rng.fill_bytes(&mut b);
                b
            }
        };
        let m = device_message(&pstmt, &env.nonce, &nh_);
        let h = msg_hash(&m);
        let ts = Instant::now();
        let (r, s) = signer.sign_message(&m)?;
        let t_signed = Instant::now();
        sign_time += t_signed - ts;
        sign_attempts += 1;
        // ECDSA verification by the holder: K = s⁻¹(h·G + r·Q), x(K) mod n = r.
        let sinv: Scalar = Option::from(s.invert()).ok_or_else(|| Error::Prover("device returned s = 0".into()))?;
        let k = (ProjectivePoint::GENERATOR * h + q * r) * sinv;
        if bool::from(k.is_identity()) || r == Scalar::ZERO || r_of(&k) != r {
            return Err(Error::Prover("device returned an invalid signature".into()));
        }
        let rinv: Scalar = Option::from(r.invert()).expect("r != 0");
        let z = s * rinv;
        let hpt = ProjectivePoint::GENERATOR * (h * rinv);
        let w = q + hpt;
        let exceptional = h == Scalar::ZERO
            || bool::from(w.is_identity())
            || bool::from(hpt.is_identity())
            || p256x::x_coord(&hpt) == p256x::x_coord(&q);
        if !exceptional {
            debug_assert_eq!(k * z, w);
            break (nh_, m, k, z, hpt, w, t_signed);
        }
        if nh.is_some() {
            return Err(Error::Prover("exceptional signature for fixed nh".into()));
        }
    };
    // Work that depends on the signature.
    let shared = link.params.profile == PROFILE_SHARED_BIT;
    let rw = (fr_rand(rng), fr_rand(rng));
    let cw = commit_point(&w, rw);
    // The link relies on Hpt being public with zero blinding: the verifier
    // recomputes C3, C4, so C2 (= y of Q) has a known opening, which the
    // restricted PA (no C2 opening proof) needs.  Do not blind Hpt.
    let ch = commit_point(&hpt, (Fr::from(0u64), Fr::from(0u64)));
    let (rq, cq) = (link.rq, link.cq);
    let link_pa = pa_prepare(
        &q,
        &hpt,
        &w,
        &[rq.0, rq.1, Fr::from(0u64), Fr::from(0u64), rw.0, rw.1],
        &[cq.0, cq.1, ch.0, ch.1, cw.0, cw.1],
        rng,
    )?;
    let rounds = sm_prepare_rounds_with(&w, &z, &k, cw, rw, shared, SM_ROUNDS, par, rng)?;
    let (out, attempt) = finish(link, &m, &nh, &k, cw, link_pa, rounds)?;
    if let Some(st) = stats {
        let t3 = Instant::now();
        *st = ProveStats {
            pre_sign: t1 - t0,
            device_sign: sign_time,
            post_sign: t3 - t_signed,
            transfer_attempts: attempt + 1,
            sign_attempts,
            bytes: out.len(),
        };
    }
    Ok(out)
}

/// Responses and encoding, once every first message is fixed.  Returns the
/// proof and the index of the transfer set used.
fn finish(
    link: KeyLink,
    m: &[u8],
    nh: &[u8; 32],
    k: &ProjectivePoint,
    cw: (TomPoint, TomPoint),
    link_pa: pa::PaState,
    rounds: Vec<SmRound>,
) -> Result<(Vec<u8>, usize)> {
    let sm_ann = encode_sm_first(&rounds);
    let mut link_pts = [TomPoint::default(); LINK_POINTS];
    link_pts[0] = cw.0;
    link_pts[1] = cw.1;
    link_pts[2..].copy_from_slice(&link_pa.ann);
    let link_first_bytes = encode_link_first(&link_pts);
    let k33 = p256x::encode(k);
    let md = sha256(m);
    let (attempt, mm, resp) = link.respond_transfer(|tr_ann| {
        binding_digest(&md, &k33, tr_ann, &link.oc_first_bytes, &link_first_bytes, &sm_ann)
    })?;
    let ch = Challenges::derive(&mm, resp.len(), &link.params)?;
    let e_link = link_challenge(&mm)?;
    let mut wr = Writer::new();
    wr.raw(MAGIC_HASHED).raw(nh).raw(&k33);
    link.write_t_and_transfer(&mut wr, attempt, &resp);
    wr.raw(&link.oc_first_bytes);
    for v in link.oncurve.respond(ch.e_oc).iter() {
        wr.raw(&fr_to_be(v));
    }
    wr.raw(&link_first_bytes);
    for v in link_pa.respond(e_link).iter() {
        wr.raw(&fr_to_be(v));
    }
    let resps = rounds.into_iter().enumerate().map(|(i, rd)| rd.respond(ch.bits[i], ch.es[i])).collect();
    write_sm(&mut wr, &sm_ann, resps);
    Ok((wr.into_bytes(), attempt))
}

/// INTENTIONALLY UNSAFE test hooks (feature `insecure-test-controls`):
/// assemble a hashed-mode proof from caller-chosen parts, without any of
/// the honest prover's consistency checks, to test that the verifier
/// rejects malicious provers.
#[cfg(feature = "insecure-test-controls")]
pub mod insecure_test_controls {
    use super::*;

    /// Encode a proof from an arbitrary link state, device message m, salt
    /// nh, nonce point K, C_W, link PA state and SM rounds.
    #[allow(clippy::too_many_arguments)]
    pub fn assemble(
        link: KeyLink,
        m: &[u8],
        nh: &[u8; 32],
        k: &ProjectivePoint,
        cw: (TomPoint, TomPoint),
        link_pa: pa::PaState,
        rounds: Vec<SmRound>,
    ) -> Result<Vec<u8>> {
        finish(link, m, nh, k, cw, link_pa, rounds).map(|x| x.0)
    }
}

// ----------------------------------------------------------------- verify
/// Parsed hashed-mode proof (public data only).
pub struct ParsedHashed {
    pub nh: [u8; 32],
    pub k: ProjectivePoint,
    pub k33: [u8; 33],
    pub common: Common,
    pub link_first: [TomPoint; LINK_POINTS],
    pub link_first_bytes: Vec<u8>,
    pub link_z: [Fr; pa::N_RESP],
}

/// Strict parser; every dimension from the request parameters and schema.
pub fn parse(b: &[u8], view: &CommittedView, params: &EcdsaParams) -> Result<ParsedHashed> {
    let d = dims(view, params)?;
    let mut rd = Reader::new(b, bbs_cd_plugin::params::MAX_PLUGIN_PROOF)?;
    if rd.take(4)? != MAGIC_HASHED {
        return bbs_cd_plugin::error::decode("magic");
    }
    let nh: [u8; 32] = rd.arr()?;
    let k33: [u8; 33] = rd.arr()?;
    let k = p256x::decode_point(&k33)?;
    let mut common = read_t_transfer_oc(&mut rd, d.n, &d.bounds, d.entries)?;
    let link_first_bytes = rd.take(LINK_POINTS * 33)?.to_vec();
    let mut link_first = [TomPoint::default(); LINK_POINTS];
    for (i, p) in link_first.iter_mut().enumerate() {
        *p = tom::decode_point(&link_first_bytes[i * 33..(i + 1) * 33], i != LINK_U1)?;
    }
    let mut link_z = [Fr::default(); pa::N_RESP];
    for v in link_z.iter_mut() {
        *v = fr_from_canonical(&rd.arr()?)?;
    }
    read_sm(&mut rd, &mut common)?;
    rd.end()?;
    Ok(ParsedHashed { nh, k, k33, common, link_first, link_first_bytes, link_z })
}

/// Binding digest M′ and SM bits of a hashed-mode proof (tests/diagnostics).
pub fn recompute_challenges(
    env: &EnvContext,
    view: &CommittedView,
    params_bytes: &[u8],
    proof: &[u8],
) -> Result<([u8; 32], [u8; SM_ROUNDS])> {
    let params = EcdsaParams::decode(params_bytes)?;
    let pr = parse(proof, view, &params)?;
    let c = &pr.common;
    let pstmt = plugin_statement(env, &view.attribute.name, params_bytes, None, &c.t_bytes);
    let m = device_message(&pstmt, &env.nonce, &pr.nh);
    let mm =
        binding_digest(&sha256(&m), &pr.k33, &c.tr_ann_bytes, &c.oc_first_bytes, &pr.link_first_bytes, &c.sm_ann_bytes);
    Ok((mm, sm_bits(&mm)))
}

#[derive(Clone, Debug, Default)]
pub struct VerifyTimes {
    pub parse: Duration,
    pub link: Duration,
    pub checks: CheckTimes,
}

#[allow(clippy::too_many_arguments)]
pub fn verify(
    env: &EnvContext,
    view: &CommittedView,
    params_bytes: &[u8],
    params: &EcdsaParams,
    proof: &[u8],
    mode: VerifyMode,
    par: Parallelism,
    rng: &mut dyn RngCore,
) -> Result<VerifyTimes> {
    let t0 = Instant::now();
    let pr = parse(proof, view, params)?;
    let t_parse = t0.elapsed();
    let c = &pr.common;
    let pstmt = plugin_statement(env, &view.attribute.name, params_bytes, None, &c.t_bytes);
    let m = device_message(&pstmt, &env.nonce, &pr.nh);
    let h = msg_hash(&m);
    if h == Scalar::ZERO {
        return rej("h == 0");
    }
    let r = r_of(&pr.k);
    if r == Scalar::ZERO {
        return rej("r == 0");
    }
    let rinv: Scalar = Option::from(r.invert()).expect("r != 0");
    let hpt = ProjectivePoint::GENERATOR * (h * rinv);
    let mm =
        binding_digest(&sha256(&m), &pr.k33, &c.tr_ann_bytes, &c.oc_first_bytes, &pr.link_first_bytes, &c.sm_ann_bytes);
    let ch = Challenges::derive(&mm, c.tr.len(), params)?;
    let e_link = link_challenge(&mm)?;
    let d = dims(view, params)?;
    let cq = fold_t(c, view, params)?;
    let cw = (pr.link_first[0], pr.link_first[1]);
    // link PA: Q (committed by the fold) + Hpt (public) = W (committed)
    let t_l = Instant::now();
    let chp = commit_point(&hpt, (Fr::from(0u64), Fr::from(0u64)));
    let c6 = [cq.0, cq.1, chp.0, chp.1, cw.0, cw.1];
    let ann: [TomPoint; pa::N_ANN] = pr.link_first[2..].try_into().unwrap();
    if !pa_verify(&c6, &ann, e_link, &pr.link_z) {
        return rej("link");
    }
    let t_link = t_l.elapsed();
    let checks = run_checks(mode, c, view, &ch, &d.bounds, d.reps, cq, &pr.k, cw, rng, par)?;
    Ok(VerifyTimes { parse: t_parse, link: t_link, checks })
}
