//! Parts shared by both modes: the committed key link (limb commitments T_j,
//! transfer sets, on-curve proof), the plugin statement, challenge
//! derivation, the common proof sections and their verification.
use std::time::{Duration, Instant};

use bbs_cd::primitives::{decode_G1, expand_message, point_to_octets_E1, scalar_from_octets, scalar_to_octets};
use bbs_cd::utils::commitment_generators;
use bbs_cd_plugin::codec::{Reader, Writer};
use bbs_cd_plugin::error::{decode, Error, Result};
use bbs_cd_plugin::issuer::{scalar_to_u128, SUITE};
use bbs_cd_plugin::par::{self, Parallelism};
use bbs_cd_plugin::plugin::{CommittedInput, CommittedView, EnvContext};
use bbs_cd_plugin::schema::AttributeSpec;
use bbs_cd_plugin::transcript::Transcript;
use bls12_381::{G1Projective, Scalar as BlsScalar};
use cd_tom256::batch::{self, TomBatch};
use cd_tom256::config::{check_limb_bits, n_limbs};
use cd_tom256::oncurve::{self, OnCurveState};
use cd_tom256::p256x;
use cd_tom256::params::SM_ROUNDS;
use cd_tom256::sm::{commit_point, decode_sm_points, sm_verify_round, SmResponse, SM_FIRST_BYTES};
use cd_tom256::tom::{self, fr_from_canonical, fr_rand, fr_to_be, Fr, TomPoint};
use cd_tom256::transfer::{
    dleq_prepare, dleq_respond, dleq_verify, fold, fold_fr, transfer_ann_bytes, Bounds, DleqPrepared,
};
use num_bigint::BigUint;
use p256::{ProjectivePoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::params::*;

// ------------------------------------------------------------ attribute
/// Limb size of a device-key attribute that may be used in `mode`, checked
/// against its layout.  A key attested for the other mode is refused (H-2).
pub fn key_limb_bits(attr: &AttributeSpec, mode: Mode) -> Result<u8> {
    let s = attr
        .scalars_spec()
        .ok_or_else(|| Error::Reject(format!("ecdsa-pop: {} is not a device-key attribute", attr.name)))?;
    match Mode::for_key_type(&s.type_id) {
        Some(m) if m == mode => {}
        Some(m) => {
            return Err(Error::Reject(format!(
                "ecdsa-pop: {} holds a key for {} mode only, not {} mode",
                attr.name,
                m.name(),
                mode.name()
            )))
        }
        None => return Err(Error::Reject(format!("ecdsa-pop: {} is not a device-key attribute", attr.name))),
    }
    let bits: u8 = s.bits.try_into().map_err(|_| Error::Reject("ecdsa-pop: limb size".into()))?;
    check_limb_bits(bits).map_err(|e| Error::Reject(format!("ecdsa-pop: {e}")))?;
    if s.count as usize != n_limbs(bits) {
        return Err(Error::Reject("ecdsa-pop: limb count".into()));
    }
    Ok(bits)
}

/// Request policy shared by the verifier and the prover: the attribute's
/// key usage must match the requested mode.
pub fn check_params(attr: &AttributeSpec, params: &EcdsaParams) -> Result<u8> {
    let bits = key_limb_bits(attr, params.mode)?;
    params.transfer.validate(bits)?;
    if !is_known_profile(&params.profile) {
        return Err(Error::Reject("ecdsa-pop: unknown profile".into()));
    }
    Ok(bits)
}

// ------------------------------------------------------------- key link
/// Transfer responses (z, s1, s2) of one accepted set.
pub type TransferResponses = Vec<(BigUint, BlsScalar, Fr)>;

/// Offline state linking the ETSI commitments D_j of the key limbs to
/// Tom-256: limb commitments T_j, transfer sets and the on-curve proof.
/// Private prover state; single use.
pub struct KeyLink {
    pub params: EcdsaParams,
    pub limb_bits: u8,
    pub q: ProjectivePoint,
    pub limbs: Vec<u128>,
    pub openings: Vec<BlsScalar>,
    pub d: Vec<G1Projective>,
    pub rho: Vec<Fr>,
    pub t_bytes: Vec<[u8; 33]>,
    pub bounds: Bounds,
    /// Primary set plus spares; each set holds 2k·R entries (limb-major).
    pub transfer_sets: Vec<Vec<DleqPrepared>>,
    pub rq: (Fr, Fr),
    pub cq: (TomPoint, TomPoint),
    pub oncurve: OnCurveState,
    pub oc_first_bytes: Vec<u8>,
}

pub fn prepare_link<R: RngCore + CryptoRng>(
    input: &CommittedInput,
    params: &EcdsaParams,
    spare_sets: usize,
    par: Parallelism,
    rng: &mut R,
) -> Result<KeyLink> {
    let limb_bits = check_params(&input.attribute, params).map_err(|e| Error::Prover(e.to_string()))?;
    let n = input.messages.len();
    let mut limbs = Vec::with_capacity(n);
    let mut openings = Vec::with_capacity(n);
    for m in &input.messages {
        let l = scalar_to_u128(&m.value).ok_or_else(|| Error::Prover("key limb out of range".into()))?;
        limbs.push(l);
        openings.push(m.opening.to_scalar()?);
    }
    let q = p256x::point_from_limbs(&limbs, limb_bits).map_err(|e| Error::Prover(format!("committed key: {e}")))?;
    let d: Vec<G1Projective> = input.messages.iter().map(|m| m.commitment).collect();
    let rho: Vec<Fr> = (0..n).map(|_| fr_rand(rng)).collect();
    let t: Vec<TomPoint> = (0..n).map(|j| tom::commit(Fr::from(limbs[j]), rho[j])).collect();
    let t_bytes: Vec<[u8; 33]> = t.iter().map(|p| tom::encode(p, true)).collect();
    let (y0, y1) = commitment_generators(SUITE, &SUITE.api_id())?;
    let bounds = Bounds::new(limb_bits, &params.transfer);
    let per_set = n * params.transfer.reps as usize;
    // one ChaCha20 stream per transfer entry: same output for any `par`
    let mut entries = par::map(par, par::child_rngs(rng, (1 + spare_sets) * per_set), |mut r| {
        dleq_prepare(&y0, &y1, &bounds, &mut r)
    })
    .into_iter();
    let transfer_sets = (0..1 + spare_sets).map(|_| entries.by_ref().take(per_set).collect()).collect();
    let rq = fold_fr(&rho, limb_bits);
    let cq = commit_point(&q, rq);
    if cq != fold(&t, limb_bits) {
        return Err(Error::Prover("fold mismatch".into()));
    }
    let (x, y) = p256x::coords_fr(&q);
    let oncurve = oncurve::oncurve_prepare(x, y, rq.0, rq.1, &cq.0, &cq.1, rng);
    let oc_first_bytes = tom::encode_batch(&oncurve.first, |_| true).concat();
    Ok(KeyLink {
        params: params.clone(),
        limb_bits,
        q,
        limbs,
        openings,
        d,
        rho,
        t_bytes,
        bounds,
        transfer_sets,
        rq,
        cq,
        oncurve,
        oc_first_bytes,
    })
}

impl KeyLink {
    /// Check, before signing, that the link belongs to this request input.
    pub fn check_input(&self, input: &CommittedInput, params: &[u8]) -> Result<()> {
        if params != self.params.encode().as_slice() {
            return Err(Error::Prover("ecdsa-pop: slot prepared for other parameters".into()));
        }
        if input.messages.iter().map(|m| m.commitment).collect::<Vec<_>>() != self.d {
            return Err(Error::Prover("ecdsa-pop: slot prepared for other commitments".into()));
        }
        Ok(())
    }

    /// Transfer responses for the first set that does not abort.
    /// Returns (set index, responses).  Discards every aborted set (D-11).
    pub fn respond_transfer<F>(&self, m_of: F) -> Result<(usize, [u8; 32], TransferResponses)>
    where
        F: Fn(&[u8]) -> [u8; 32],
    {
        let reps = self.params.transfer.reps as usize;
        for (attempt, set) in self.transfer_sets.iter().enumerate() {
            let m = m_of(&transfer_ann_bytes(set));
            let cs = transfer_challenges(&m, set.len(), self.params.transfer.b_c);
            let mut resp = Vec::with_capacity(set.len());
            for (i, d) in set.iter().enumerate() {
                let j = i / reps;
                match dleq_respond(d, self.limbs[j], &self.openings[j], &self.rho[j], &cs[i], &self.bounds) {
                    Some(x) => resp.push(x),
                    None => break,
                }
            }
            if resp.len() == set.len() {
                return Ok((attempt, m, resp));
            }
        }
        Err(Error::Prover("transfer spare sets exhausted; slot burned".into()))
    }

    /// Write T_j, the accepted transfer set and its responses.
    pub fn write_t_and_transfer(&self, w: &mut Writer, attempt: usize, resp: &[(BigUint, BlsScalar, Fr)]) {
        for tb in &self.t_bytes {
            w.raw(tb);
        }
        for (d, (z, s1, s2)) in self.transfer_sets[attempt].iter().zip(resp) {
            w.raw(&point_to_octets_E1(&d.big_k1)).raw(&tom::encode(&d.big_k2, true));
            w.big(z, self.bounds.z_bytes).raw(&scalar_to_octets(s1)).raw(&fr_to_be(s2));
        }
    }
}

// ------------------------------------------------- statement, challenges
/// Plugin statement: binds the envelope, the plugin's position, attribute
/// and parameters, the limb commitments T_j and (raw mode) Q′.
pub fn plugin_statement(
    env: &EnvContext,
    attribute: &str,
    params: &[u8],
    qprime: Option<&[u8; 33]>,
    t_bytes: &[[u8; 33]],
) -> Vec<u8> {
    let mut t = Transcript::new(DST_STMT)
        .add(b"plugin", PLUGIN_ID)
        .add(b"plugin_index", &env.plugin_index.to_be_bytes())
        .add(b"attribute", attribute.as_bytes())
        .add(b"params", params)
        .add(b"env", &env.env);
    if let Some(q) = qprime {
        t = t.add(b"Qprime", q);
    }
    t.add(b"T", &t_bytes.concat()).into_bytes()
}

/// Transfer challenges: entry i = limb·R + repetition, b_c bits each.
pub fn transfer_challenges(m: &[u8; 32], n_entries: usize, b_c: u16) -> Vec<BigUint> {
    (0..n_entries)
        .map(|i| {
            let d = Transcript::new(DST_TR).add(b"M", m).add(b"i", &(i as u16).to_be_bytes()).digest();
            BigUint::from_bytes_be(&d[..(b_c / 8) as usize])
        })
        .collect()
}

/// 128 SM bits: SHAKE256(transcript), LSB-first within each byte.
pub fn sm_bits(m: &[u8; 32]) -> [u8; SM_ROUNDS] {
    let data = Transcript::new(DST_SM).add(b"M", m).into_bytes();
    let mut h = sha3::Shake256::default();
    h.update(&data);
    let mut out = [0u8; SM_ROUNDS / 8];
    h.finalize_xof().read(&mut out);
    std::array::from_fn(|i| (out[i / 8] >> (i % 8)) & 1)
}

pub fn hash_to_fr(msg: &[u8], dst: &[u8]) -> Result<Fr> {
    let u = expand_message(SUITE, msg, dst, 48)?;
    Ok(tom::fr_from_be(&u))
}

pub fn pa_challenges(m: &[u8; 32], profile: &[u8], bits: &[u8; SM_ROUNDS]) -> Result<Vec<Fr>> {
    if profile == PROFILE_SHARED_BIT {
        return Ok(bits.iter().map(|&b| Fr::from(b as u64)).collect());
    }
    if profile == PROFILE_SEPARATE_PA {
        return (0..SM_ROUNDS)
            .map(|i| {
                let msg = Transcript::new(DST_PA).add(b"M", m).add(b"round", &(i as u16).to_be_bytes()).into_bytes();
                hash_to_fr(&msg, DST_PA_H2F)
            })
            .collect();
    }
    Err(Error::Reject("unknown profile".into()))
}

/// On-curve proof challenge (full Z_p).
pub fn oc_challenge(m: &[u8; 32]) -> Result<Fr> {
    hash_to_fr(&Transcript::new(DST_OC).add(b"M", m).into_bytes(), DST_OC_H2F)
}

/// Fiat–Shamir challenges of the proof (all from the binding digest M′).
pub struct Challenges {
    pub cs: Vec<BigUint>,
    pub e_oc: Fr,
    pub bits: [u8; SM_ROUNDS],
    pub es: Vec<Fr>,
}

impl Challenges {
    pub fn derive(m: &[u8; 32], n_entries: usize, params: &EcdsaParams) -> Result<Self> {
        let bits = sm_bits(m);
        Ok(Challenges {
            cs: transfer_challenges(m, n_entries, params.transfer.b_c),
            e_oc: oc_challenge(m)?,
            es: pa_challenges(m, &params.profile, &bits)?,
            bits,
        })
    }
}

/// Write the 128 SM rounds (first message, α, blinds, 12 PA responses).
pub fn write_sm(w: &mut Writer, sm_ann: &[u8], resps: Vec<SmResponse>) {
    w.u16(resps.len() as u16);
    for (k, SmResponse { alpha, rr, z }) in resps.into_iter().enumerate() {
        w.raw(&sm_ann[k * SM_FIRST_BYTES..(k + 1) * SM_FIRST_BYTES]);
        w.raw(&p256x::scalar_to_be(&alpha)).raw(&fr_to_be(&rr.0)).raw(&fr_to_be(&rr.1));
        for v in &z {
            w.raw(&fr_to_be(v));
        }
    }
}

// ------------------------------------------------------ parsed sections
pub struct TransferEntry {
    pub k1: G1Projective,
    pub k2: TomPoint,
    pub z: BigUint,
    pub s1: BlsScalar,
    pub s2: Fr,
}

/// Sections common to both modes (T_j, transfer, on-curve, SM).
pub struct Common {
    pub t: Vec<TomPoint>,
    pub t_bytes: Vec<[u8; 33]>,
    pub tr: Vec<TransferEntry>,
    pub tr_ann_bytes: Vec<u8>,
    pub oc_first: [TomPoint; oncurve::N_FIRST],
    pub oc_first_bytes: Vec<u8>,
    pub oc_z: [Fr; oncurve::N_RESP],
    pub sm_ann_bytes: Vec<u8>,
    pub sm_resp: Vec<SmResponse>,
}

pub fn p256_scalar_nonzero(b: &[u8; 32]) -> Result<Scalar> {
    let s = p256x::scalar_from_canonical(b)?;
    if s == Scalar::ZERO {
        return decode("P-256 scalar is zero");
    }
    Ok(s)
}

/// Read T_j, the transfer entries and the on-curve proof.
pub fn read_t_transfer_oc(rd: &mut Reader, n: usize, bounds: &Bounds, entries: usize) -> Result<Common> {
    let mut t_bytes = Vec::with_capacity(n);
    let mut t = Vec::with_capacity(n);
    for _ in 0..n {
        let tb: [u8; 33] = rd.arr()?;
        t.push(tom::decode_point(&tb, true)?);
        t_bytes.push(tb);
    }
    let mut tr = Vec::with_capacity(entries);
    let mut tr_ann = Vec::with_capacity(entries * 81);
    for _ in 0..entries {
        let k1b: [u8; 48] = rd.arr()?;
        let k2b: [u8; 33] = rd.arr()?;
        let k1 = decode_G1(&k1b, true).map_err(|_| Error::Decode("transfer K1".into()))?;
        let k2 = tom::decode_point(&k2b, true)?;
        let z = rd.big(bounds.z_bytes, &bounds.z_lo, &bounds.z_hi)?;
        let s1 = scalar_from_octets(rd.take(32)?).map_err(|_| Error::Decode("transfer s1 >= r".into()))?;
        let s2 = fr_from_canonical(&rd.arr()?)?;
        tr.push(TransferEntry { k1, k2, z, s1, s2 });
        tr_ann.extend_from_slice(&k1b);
        tr_ann.extend_from_slice(&k2b);
    }
    let oc_first_bytes = rd.take(oncurve::N_FIRST * 33)?.to_vec();
    let mut oc_first = [TomPoint::default(); oncurve::N_FIRST];
    for (i, p) in oc_first.iter_mut().enumerate() {
        *p = tom::decode_point(&oc_first_bytes[i * 33..(i + 1) * 33], true)?;
    }
    let mut oc_z = [Fr::default(); oncurve::N_RESP];
    for v in oc_z.iter_mut() {
        *v = fr_from_canonical(&rd.arr()?)?;
    }
    Ok(Common {
        t,
        t_bytes,
        tr,
        tr_ann_bytes: tr_ann,
        oc_first,
        oc_first_bytes,
        oc_z,
        sm_ann_bytes: vec![],
        sm_resp: vec![],
    })
}

/// Read the SM section (length-checked; points decoded later).
pub fn read_sm(rd: &mut Reader, c: &mut Common) -> Result<()> {
    let nr = rd.u16()? as usize;
    if nr != SM_ROUNDS {
        return decode("SM round count");
    }
    c.sm_ann_bytes.reserve(SM_ROUNDS * SM_FIRST_BYTES);
    c.sm_resp.reserve(SM_ROUNDS);
    for _ in 0..nr {
        c.sm_ann_bytes.extend_from_slice(rd.take(SM_FIRST_BYTES)?);
        let alpha = p256_scalar_nonzero(&rd.arr()?)?;
        let rr = (fr_from_canonical(&rd.arr()?)?, fr_from_canonical(&rd.arr()?)?);
        let mut z = [Fr::default(); 12];
        for v in z.iter_mut() {
            *v = fr_from_canonical(&rd.arr()?)?;
        }
        c.sm_resp.push(SmResponse { alpha, rr, z });
    }
    Ok(())
}

pub fn rej<T>(s: impl Into<String>) -> Result<T> {
    Err(Error::Reject(s.into()))
}

/// How the linear group equations are checked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VerifyMode {
    /// One random linear combination per group (weights ≥ 128 bits from the
    /// verifier's RNG, drawn after parsing).  On failure the individual
    /// checks run to name the failing equation.
    #[default]
    Batch,
    /// Every equation checked on its own (the reference behaviour).
    Individual,
}

/// Times of the proof checks.
#[derive(Clone, Debug, Default)]
pub struct CheckTimes {
    pub transfer: Duration,
    pub oncurve: Duration,
    pub sm: Duration,
}

/// Reference path: transfer, on-curve and SM, every equation on its own.
/// `sm_base` is the SM base (Q′ or K), `sm_result` the commitment to the
/// SM result (the fold of T_j, or C_W).
#[allow(clippy::too_many_arguments)]
pub fn individual_checks(
    c: &Common,
    view: &CommittedView,
    ch: &Challenges,
    bounds: &Bounds,
    reps: usize,
    cq: (TomPoint, TomPoint),
    sm_base: &ProjectivePoint,
    sm_result: (TomPoint, TomPoint),
    par: Parallelism,
) -> Result<CheckTimes> {
    let t = Instant::now();
    let (y0, y1) = commitment_generators(SUITE, &SUITE.api_id())?;
    for (i, e) in c.tr.iter().enumerate() {
        let j = i / reps;
        if !dleq_verify(&view.commitments[j], &c.t[j], &e.k1, &e.k2, &ch.cs[i], &e.z, &e.s1, &e.s2, &y0, &y1, bounds) {
            return rej(format!("transfer[{j}.{}]", i % reps));
        }
    }
    let t_tr = t.elapsed();
    let t = Instant::now();
    if !oncurve::oncurve_verify(&cq.0, &cq.1, &c.oc_first, ch.e_oc, &c.oc_z) {
        return rej("on-curve");
    }
    let t_oc = t.elapsed();
    let t = Instant::now();
    let first = decode_sm_points(&c.sm_ann_bytes, SM_ROUNDS, par)?;
    let failing = par::map(par, par::chunks(par, SM_ROUNDS), |rg| {
        rg.into_iter().find(|&i| !sm_verify_round(sm_base, sm_result, &first[i], &c.sm_resp[i], ch.bits[i], ch.es[i]))
    });
    if let Some(i) = failing.into_iter().flatten().next() {
        return rej(format!("sm[{i}]"));
    }
    Ok(CheckTimes { transfer: t_tr, oncurve: t_oc, sm: t.elapsed() })
}

/// Batch path.  `Ok(Some(times))` = every batch holds; `Ok(None)` = some
/// check failed (the caller runs `individual_checks` for the reason).
#[allow(clippy::too_many_arguments)]
pub fn batch_checks(
    c: &Common,
    view: &CommittedView,
    ch: &Challenges,
    bounds: &Bounds,
    reps: usize,
    cq: (TomPoint, TomPoint),
    sm_base: &ProjectivePoint,
    sm_result: (TomPoint, TomPoint),
    rng: &mut dyn RngCore,
    par: Parallelism,
) -> Result<Option<CheckTimes>> {
    let t = Instant::now();
    let first = decode_sm_points(&c.sm_ann_bytes, SM_ROUNDS, par)?;
    let t_dec = t.elapsed();
    let mut rng = rng;
    let t = Instant::now();
    let (y0, y1) = commitment_generators(SUITE, &SUITE.api_id())?;
    let g1: Vec<batch::G1Entry> = c
        .tr
        .iter()
        .enumerate()
        .map(|(i, e)| batch::G1Entry { d: &view.commitments[i / reps], k1: &e.k1, c: &ch.cs[i], z: &e.z, s1: &e.s1 })
        .collect();
    if !batch::g1_transfer_batch(&mut rng, &g1, bounds, &y0, &y1) {
        return Ok(None);
    }
    let mut tb = TomBatch::with_capacity(c.tr.len() * 2 + 16 + SM_ROUNDS * 14);
    for (i, e) in c.tr.iter().enumerate() {
        if !tb.add_transfer(&mut rng, bounds, &c.t[i / reps], &e.k2, &ch.cs[i], &e.z, &e.s2) {
            return Ok(None);
        }
    }
    let t_tr = t.elapsed();
    let t = Instant::now();
    tb.add_oncurve(&mut rng, &c.oc_first, ch.e_oc, &c.oc_z);
    let t_oc = t.elapsed();
    let t = Instant::now();
    if sm_result != cq {
        // the SM result is not the fold: move the shared coefficients first
        tb.absorb_shared(&cq.0, &cq.1);
    }
    // All SM weights are drawn here, in round order, before any parallel
    // work, so the combination does not depend on `par`.
    let weights: Vec<[Fr; 10]> = (0..SM_ROUNDS).map(|_| batch::sm_weights(&mut rng)).collect();
    // W_i = α_i·base through a per-verification fixed-base table.
    let table = cd_tom256::comb::P256Comb::new(*sm_base, 4);
    let parts = par::map(par, par::chunks(par, SM_ROUNDS), |rg| {
        let mut b = TomBatch::with_capacity(rg.len() * 14);
        for i in rg {
            let w = table.mul(&c.sm_resp[i].alpha);
            if !b.add_sm_round_weighted(&weights[i], &w, &first[i], &c.sm_resp[i], ch.bits[i], ch.es[i]) {
                return None;
            }
        }
        Some(b)
    });
    for part in parts {
        match part {
            Some(b) => tb.merge(b),
            None => return Ok(None),
        }
    }
    if !tb.check_par(&sm_result.0, &sm_result.1, par) {
        return Ok(None);
    }
    Ok(Some(CheckTimes { transfer: t_tr, oncurve: t_oc, sm: t_dec + t.elapsed() }))
}

/// Run the checks in `mode`; in batch mode a failure is re-run individually
/// to name the failing equation.
#[allow(clippy::too_many_arguments)]
pub fn run_checks(
    mode: VerifyMode,
    c: &Common,
    view: &CommittedView,
    ch: &Challenges,
    bounds: &Bounds,
    reps: usize,
    cq: (TomPoint, TomPoint),
    sm_base: &ProjectivePoint,
    sm_result: (TomPoint, TomPoint),
    rng: &mut dyn RngCore,
    par: Parallelism,
) -> Result<CheckTimes> {
    match mode {
        VerifyMode::Individual => individual_checks(c, view, ch, bounds, reps, cq, sm_base, sm_result, par),
        VerifyMode::Batch => match batch_checks(c, view, ch, bounds, reps, cq, sm_base, sm_result, rng, par)? {
            Some(t) => Ok(t),
            None => {
                individual_checks(c, view, ch, bounds, reps, cq, sm_base, sm_result, par)?;
                debug_assert!(false, "batch rejected but every individual check passed");
                rej("internal: batch and individual verification disagree")
            }
        },
    }
}

/// Dimensions every parser takes from the request and the schema.
pub struct Dims {
    pub n: usize,
    pub entries: usize,
    pub bounds: Bounds,
    pub reps: usize,
}

pub fn dims(view: &CommittedView, params: &EcdsaParams) -> Result<Dims> {
    let bits = check_params(&view.attribute, params)?;
    let n = n_limbs(bits);
    if view.commitments.len() != n {
        return rej("ecdsa-pop: commitment count");
    }
    let reps = params.transfer.reps as usize;
    Ok(Dims { n, entries: n * reps, bounds: Bounds::new(bits, &params.transfer), reps })
}

/// Fold of the T_j for this attribute's limb size.
pub fn fold_t(c: &Common, view: &CommittedView, params: &EcdsaParams) -> Result<(TomPoint, TomPoint)> {
    Ok(fold(&c.t, key_limb_bits(&view.attribute, params.mode)?))
}

// ------------------------------------------------------------ layout
/// Byte ranges of the sections of an `ecdsa-pop` proof (relative to the
/// start of the plugin proof).  For tests, size checks and tamper tooling.
#[derive(Clone, Debug, Default)]
pub struct Segments {
    pub magic: (usize, usize),
    pub nh: (usize, usize),
    /// Q′ (raw) or K (hashed).
    pub point: (usize, usize),
    /// ECDSA r and s′ (raw mode only; empty ranges in hashed mode).
    pub r: (usize, usize),
    pub s: (usize, usize),
    pub t: Vec<(usize, usize)>,
    /// Transfer entries (limb-major) and, within each, the z field.
    pub tr: Vec<(usize, usize)>,
    pub tr_z: Vec<(usize, usize)>,
    pub oc: (usize, usize),
    /// Link section (hashed mode only; empty range in raw mode).
    pub link: (usize, usize),
    /// SM rounds (after the u16 round count).
    pub sm: (usize, usize),
    /// Total proof size.
    pub len: usize,
}

/// Layout of a proof for `params` on attribute `attr`.  Every honest proof
/// has exactly this size.
pub fn segments(attr: &AttributeSpec, params: &EcdsaParams) -> Result<Segments> {
    use cd_tom256::oncurve::OC_BYTES;
    use cd_tom256::sm::SM_ROUND_BYTES;
    use cd_tom256::transfer::transfer_entry_bytes;
    let bits = check_params(attr, params)?;
    let n = n_limbs(bits);
    let entries = n * params.transfer.reps as usize;
    let zb = params.transfer.z_bytes(bits);
    let te = transfer_entry_bytes(zb);
    let mut s = Segments { magic: (0, 4), nh: (4, 36), point: (36, 69), ..Default::default() };
    let mut o = 69;
    if params.mode == Mode::Raw {
        s.r = (o, o + 32);
        s.s = (o + 32, o + 64);
        o += 64;
    }
    for _ in 0..n {
        s.t.push((o, o + 33));
        o += 33;
    }
    for _ in 0..entries {
        s.tr.push((o, o + te));
        s.tr_z.push((o + 81, o + 81 + zb));
        o += te;
    }
    s.oc = (o, o + OC_BYTES);
    o += OC_BYTES;
    if params.mode == Mode::Hashed {
        s.link = (o, o + crate::hashed::LINK_BYTES);
        o += crate::hashed::LINK_BYTES;
    }
    o += 2;
    s.sm = (o, o + SM_ROUNDS * SM_ROUND_BYTES);
    s.len = s.sm.1;
    Ok(s)
}
