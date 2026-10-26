//! Raw mode (feature `raw-mode`): precomputed blinded-key device binding
//! (DEVBIND 0.3 construction, new envelope and wire format).
//!
//!  prepare  offline: a, c = 1/a, Q′ = aQ; limb commitments T_j; transfer
//!           sets; on-curve proof; 128 SM rounds proving Q = c·Q′.
//!  prove    online: h = H(Tr(pstmt incl. Q′ and T_j; nv; nh)) mod n; the
//!           device raw-signs c·h under Q; s′ = a·s (low-s) is an ordinary
//!           ECDSA signature on h under Q′; binding digest M′; transfer,
//!           on-curve and SM challenges from M′ only.
//!  verify   h, ECDSA under Q′, transfer, fold, on-curve proof, SM.
//!
//! Security rests on KR-ECDSA (key-randomized raw-representative
//! unforgeability).  Q′ **must** be in the signed hash: without it a raw
//! signature on any value can be rescaled (the insecure control below).
use std::time::{Duration, Instant};

use bbs_cd_plugin::codec::{Reader, Writer};
use bbs_cd_plugin::error::{Error, Result};
use bbs_cd_plugin::par::Parallelism;
use bbs_cd_plugin::plugin::{CommittedInput, CommittedView, EnvContext};
use bbs_cd_plugin::transcript::{sha256, Transcript};
use cd_tom256::p256x;
use cd_tom256::params::SM_ROUNDS;
use cd_tom256::sm::{encode_sm_first, sm_prepare_rounds_with, SmRound};
use cd_tom256::tom::fr_to_be;
use p256::elliptic_curve::Field as _;
use p256::{ProjectivePoint, Scalar};
use rand_core::{CryptoRng, RngCore};

use crate::common::*;
use crate::device::{ecdsa_verify_prehashed, RawSigner};
use crate::params::*;
use crate::ProveStats;

/// How h is computed.  The public API always uses `Candidate`.  The control
/// omits Q′ from the signed hash and is INTENTIONALLY VULNERABLE; it is
/// reachable only through `insecure_test_controls`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HMode {
    Candidate,
    #[cfg_attr(not(feature = "insecure-test-controls"), allow(dead_code))]
    VulnerableControlNoQprime,
}

pub fn h_input(pstmt: &[u8], nonce: &[u8], nh: &[u8; 32]) -> Vec<u8> {
    Transcript::new(DST_H_RAW).add(b"statement", pstmt).add(b"nv", nonce).add(b"nh", nh).into_bytes()
}

/// h = OS2IP(SHA-256(h_input)) mod n.
pub fn rep_hash(hin: &[u8]) -> Scalar {
    p256x::scalar_reduce(&sha256(hin))
}

/// Binding digest M′ of the raw mode.
pub fn binding_digest(
    hin: &[u8],
    r: &Scalar,
    s: &Scalar,
    transfer_ann: &[u8],
    oc_first: &[u8],
    sm_ann: &[u8],
) -> [u8; 32] {
    Transcript::new(DST_M_RAW)
        .add(b"h_input", &sha256(hin))
        .add(b"ecdsa_r", &p256x::scalar_to_be(r))
        .add(b"ecdsa_s", &p256x::scalar_to_be(s))
        .add(b"transfer_announcements", transfer_ann)
        .add(b"on_curve_first", oc_first)
        .add(b"sm_first_messages", sm_ann)
        .digest()
}

// ----------------------------------------------------------------- prepare
/// Offline state: the key link plus the key proof for Q′ = a·Q.  Private;
/// single use.  A cloned slot that answers twice reveals c, hence Q.
pub struct RawSlot {
    pub link: KeyLink,
    pub a: Scalar,
    pub c: Scalar,
    pub qp: ProjectivePoint,
    pub qp33: [u8; 33],
    pub rounds: Vec<SmRound>,
    pub sm_ann_bytes: Vec<u8>,
}

pub fn prepare<R: RngCore + CryptoRng>(
    input: &CommittedInput,
    params: &EcdsaParams,
    spare_sets: usize,
    a: Option<Scalar>,
    par: Parallelism,
    rng: &mut R,
) -> Result<RawSlot> {
    if params.mode != Mode::Raw {
        return Err(Error::Prover("ecdsa-pop: params are not raw mode".into()));
    }
    let link = prepare_link(input, params, spare_sets, par, rng)?;
    prepare_with_link(link, a, par, rng)
}

/// Key proof on an existing link (tests and vectors may fix `a`).
pub fn prepare_with_link<R: RngCore + CryptoRng>(
    link: KeyLink,
    a: Option<Scalar>,
    par: Parallelism,
    rng: &mut R,
) -> Result<RawSlot> {
    let a = match a {
        Some(a) => a,
        None => loop {
            let a = Scalar::random(&mut *rng);
            if a != Scalar::ZERO {
                break a;
            }
        },
    };
    let c: Scalar = Option::from(a.invert()).ok_or_else(|| Error::Prover("a out of range".into()))?;
    let qp = link.q * a;
    let shared = link.params.profile == PROFILE_SHARED_BIT;
    let rounds = sm_prepare_rounds_with(&link.q, &c, &qp, link.cq, link.rq, shared, SM_ROUNDS, par, rng)?;
    let sm_ann_bytes = encode_sm_first(&rounds);
    Ok(RawSlot { link, a, c, qp, qp33: p256x::encode(&qp), rounds, sm_ann_bytes })
}

// ------------------------------------------------------------------ prove
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_impl<R: RngCore + CryptoRng>(
    slot: RawSlot,
    env: &EnvContext,
    input: &CommittedInput,
    params: &[u8],
    signer: &dyn RawSigner,
    h_mode: HMode,
    honest_checks: bool,
    nh: Option<[u8; 32]>,
    rng: &mut R,
    stats: Option<&mut ProveStats>,
) -> Result<Vec<u8>> {
    let t0 = Instant::now();
    let RawSlot { link, a, c, qp33, rounds, sm_ann_bytes, .. } = slot;
    link.check_input(input, params)?;
    let q33 = p256x::encode(&link.q);
    if honest_checks && signer.public_key()? != q33 {
        return Err(Error::Prover("signing device does not match the committed device key".into()));
    }
    let qpart = match h_mode {
        HMode::Candidate => Some(&qp33),
        HMode::VulnerableControlNoQprime => None,
    };
    let pstmt = plugin_statement(env, &input.attribute.name, params, qpart, &link.t_bytes);
    let (nh, hin, h) = loop {
        let nh_ = match nh {
            Some(x) => x,
            None => {
                let mut b = [0u8; 32];
                rng.fill_bytes(&mut b);
                b
            }
        };
        let hin = h_input(&pstmt, &env.nonce, &nh_);
        let h = rep_hash(&hin);
        if h != Scalar::ZERO {
            break (nh_, hin, h);
        }
        if nh.is_some() {
            return Err(Error::Prover("h == 0 for fixed nh".into()));
        }
    };
    let rep = p256x::scalar_to_be(&(c * h));
    let t1 = Instant::now();
    let (r, s) = signer.sign_representative(&rep)?;
    let t2 = Instant::now();
    if honest_checks && !ecdsa_verify_prehashed(&q33, &rep, &r, &s) {
        return Err(Error::Prover("device returned an invalid signature on c*h under Q".into()));
    }
    let mut s2 = a * s;
    if p256x::is_high_s(&s2) {
        s2 = -s2;
    }
    if r == Scalar::ZERO || s2 == Scalar::ZERO {
        return Err(Error::Prover("device returned out-of-range signature".into()));
    }
    let (attempt, m, resp) =
        link.respond_transfer(|tr_ann| binding_digest(&hin, &r, &s2, tr_ann, &link.oc_first_bytes, &sm_ann_bytes))?;
    let ch = Challenges::derive(&m, resp.len(), &link.params)?;
    let mut w = Writer::new();
    w.raw(MAGIC_RAW).raw(&nh).raw(&qp33);
    w.raw(&p256x::scalar_to_be(&r)).raw(&p256x::scalar_to_be(&s2));
    link.write_t_and_transfer(&mut w, attempt, &resp);
    w.raw(&link.oc_first_bytes);
    for v in link.oncurve.respond(ch.e_oc).iter() {
        w.raw(&fr_to_be(v));
    }
    let resps = rounds.into_iter().enumerate().map(|(i, rd)| rd.respond(ch.bits[i], ch.es[i])).collect();
    write_sm(&mut w, &sm_ann_bytes, resps);
    let out = w.into_bytes();
    if let Some(st) = stats {
        let t3 = Instant::now();
        *st = ProveStats {
            pre_sign: t1 - t0,
            device_sign: t2 - t1,
            post_sign: t3 - t2,
            transfer_attempts: attempt + 1,
            sign_attempts: 1,
            bytes: out.len(),
        };
    }
    Ok(out)
}

// ----------------------------------------------------------------- verify
/// Parsed raw-mode proof (public data only).
pub struct ParsedRaw {
    pub nh: [u8; 32],
    pub qp: ProjectivePoint,
    pub qp33: [u8; 33],
    pub r: Scalar,
    pub s: Scalar,
    pub common: Common,
}

/// Strict parser; every dimension from the request parameters and schema.
pub fn parse(b: &[u8], view: &CommittedView, params: &EcdsaParams) -> Result<ParsedRaw> {
    let d = dims(view, params)?;
    let mut rd = Reader::new(b, bbs_cd_plugin::params::MAX_PLUGIN_PROOF)?;
    if rd.take(4)? != MAGIC_RAW {
        return bbs_cd_plugin::error::decode("magic");
    }
    let nh: [u8; 32] = rd.arr()?;
    let qp33: [u8; 33] = rd.arr()?;
    let qp = p256x::decode_point(&qp33)?;
    let r = p256_scalar_nonzero(&rd.arr()?)?;
    let s = p256_scalar_nonzero(&rd.arr()?)?;
    if p256x::is_high_s(&s) {
        return bbs_cd_plugin::error::decode("high s");
    }
    let mut common = read_t_transfer_oc(&mut rd, d.n, &d.bounds, d.entries)?;
    read_sm(&mut rd, &mut common)?;
    rd.end()?;
    Ok(ParsedRaw { nh, qp, qp33, r, s, common })
}

/// Binding digest M′ and SM bits of a raw-mode proof (tests/diagnostics).
pub fn recompute_challenges(
    env: &EnvContext,
    view: &CommittedView,
    params_bytes: &[u8],
    proof: &[u8],
) -> Result<([u8; 32], [u8; SM_ROUNDS])> {
    let params = EcdsaParams::decode(params_bytes)?;
    let pr = parse(proof, view, &params)?;
    let c = &pr.common;
    let pstmt = plugin_statement(env, &view.attribute.name, params_bytes, Some(&pr.qp33), &c.t_bytes);
    let hin = h_input(&pstmt, &env.nonce, &pr.nh);
    let m = binding_digest(&hin, &pr.r, &pr.s, &c.tr_ann_bytes, &c.oc_first_bytes, &c.sm_ann_bytes);
    Ok((m, sm_bits(&m)))
}

#[derive(Clone, Debug, Default)]
pub struct VerifyTimes {
    pub parse: Duration,
    pub ecdsa: Duration,
    pub checks: CheckTimes,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_impl(
    env: &EnvContext,
    view: &CommittedView,
    params_bytes: &[u8],
    params: &EcdsaParams,
    proof: &[u8],
    h_mode: HMode,
    mode: VerifyMode,
    par: Parallelism,
    rng: &mut dyn RngCore,
) -> Result<VerifyTimes> {
    let t0 = Instant::now();
    let pr = parse(proof, view, params)?;
    let t_parse = t0.elapsed();
    let c = &pr.common;
    let qpart = match h_mode {
        HMode::Candidate => Some(&pr.qp33),
        HMode::VulnerableControlNoQprime => None,
    };
    let pstmt = plugin_statement(env, &view.attribute.name, params_bytes, qpart, &c.t_bytes);
    let hin = h_input(&pstmt, &env.nonce, &pr.nh);
    let h = rep_hash(&hin);
    if h == Scalar::ZERO {
        return rej("h == 0");
    }
    let t_e = Instant::now();
    if !ecdsa_verify_prehashed(&pr.qp33, &p256x::scalar_to_be(&h), &pr.r, &pr.s) {
        return rej("ecdsa");
    }
    let t_ecdsa = t_e.elapsed();
    let m = binding_digest(&hin, &pr.r, &pr.s, &c.tr_ann_bytes, &c.oc_first_bytes, &c.sm_ann_bytes);
    let ch = Challenges::derive(&m, c.tr.len(), params)?;
    let d = dims(view, params)?;
    let cq = fold_t(c, view, params)?;
    let checks = run_checks(mode, c, view, &ch, &d.bounds, d.reps, cq, &pr.qp, cq, rng, par)?;
    Ok(VerifyTimes { parse: t_parse, ecdsa: t_ecdsa, checks })
}

/// DELIBERATELY BROKEN raw-mode variants for attack reproduction.  Compiled
/// only with the `insecure-test-controls` cargo feature, which no production
/// build may enable.  Nothing here is reachable from the normal prover or
/// verifier.
#[cfg(feature = "insecure-test-controls")]
pub mod insecure_test_controls {
    use super::*;
    use bbs_cd_plugin::plugin::{CryptoRngCore, PluginProver, PluginVerifier};
    use bbs_cd_plugin::schema::AttributeSpec;

    /// Which representative the presentation uses.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Variant {
        /// The candidate (Q′ in the signed hash).
        Candidate,
        /// INTENTIONALLY VULNERABLE: Q′ omitted from the signed hash.
        VulnerableControlNoQprime,
    }

    fn h(v: Variant) -> HMode {
        match v {
            Variant::Candidate => HMode::Candidate,
            Variant::VulnerableControlNoQprime => HMode::VulnerableControlNoQprime,
        }
    }

    /// Prover the way a MALICIOUS holder could run it: no device-key check,
    /// no raw-signature check (a malicious holder is not bound by them).
    pub struct MaliciousRawProver<'a> {
        pub slot: RawSlot,
        pub signer: &'a dyn RawSigner,
        pub variant: Variant,
        pub nh: Option<[u8; 32]>,
    }

    impl PluginProver for MaliciousRawProver<'_> {
        fn plugin_id(&self) -> &[u8] {
            PLUGIN_ID
        }
        fn prove(
            self: Box<Self>,
            env: &EnvContext,
            input: &CommittedInput,
            params: &[u8],
            rng: &mut dyn CryptoRngCore,
        ) -> Result<Vec<u8>> {
            let mut r = rng;
            prove_impl(self.slot, env, input, params, self.signer, h(self.variant), false, self.nh, &mut r, None)
        }
    }

    /// Acceptance predicate of the selected variant (raw mode only).
    pub struct VariantVerifier(pub Variant);

    impl PluginVerifier for VariantVerifier {
        fn plugin_id(&self) -> &[u8] {
            PLUGIN_ID
        }
        fn check_request(&self, attr: &AttributeSpec, params: &[u8]) -> Result<()> {
            let p = EcdsaParams::decode(params)?;
            check_params(attr, &p)?;
            if p.mode != Mode::Raw {
                return rej("variant verifier: raw mode only");
            }
            Ok(())
        }
        fn verify(
            &self,
            env: &EnvContext,
            view: &CommittedView,
            params: &[u8],
            proof: &[u8],
            rng: &mut dyn CryptoRngCore,
        ) -> Result<Vec<u8>> {
            let p = EcdsaParams::decode(params)?;
            let mut r = rng;
            verify_impl(env, view, params, &p, proof, h(self.0), VerifyMode::Batch, Parallelism::Off, &mut r)?;
            Ok(vec![])
        }
    }
}
