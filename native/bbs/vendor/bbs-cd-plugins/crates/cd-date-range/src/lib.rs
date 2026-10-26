//! `date-range`: prove that a committed date (for example a birth date) lies
//! in a range the verifier asks for, without revealing it (plugin of
//! `bbs-cd-plugin`).
//!
//! The credential holds the date as a `date-packed` attribute (one scalar,
//! [`date`]).  The verifier sends `ge` (born on or after) and/or `le` (born
//! on or before) as YYYYMMDD; the holder commits to the date in the BBS
//! presentation and proves lo ≤ m ≤ hi with a bit-decomposition range proof
//! ([`range`]) on the ETSI commitment D, natively in BLS12-381.  One
//! credential answers every cutoff and range.  Multiples of the commitment
//! generators use precomputed tables ([`fixed`]).
//!
//! Specification: `docs/plugins/DATE-RANGE.md`.
//! **Not constant-time. Not audited. Not for production.**
#![forbid(unsafe_code)]
#![allow(non_snake_case)]

use bbs_cd::primitives::point_to_octets_E1;
use bbs_cd::utils::hash_to_scalar;
use bbs_cd_plugin::codec::{Reader, Writer};
use bbs_cd_plugin::error::{Error, Result};
use bbs_cd_plugin::issuer::{scalar_to_u128, SUITE};
use bbs_cd_plugin::plugin::{CommittedInput, CommittedView, CryptoRngCore, EnvContext, PluginProver, PluginVerifier};
use bbs_cd_plugin::schema::AttributeSpec;
use bbs_cd_plugin::transcript::Transcript;
use bls12_381::{G1Projective, Scalar};

pub mod date;
pub mod fixed;
pub mod range;

pub use date::{date_input, DateHandler, Ymd, RECOMMENDED_BITS, TYPE_DATE};
use range::{Bases, ChallengeInput, Statement};

pub const PLUGIN_ID: &[u8] = b"date-range/0.1";
const DST_CHALLENGE: &[u8] = b"DATE-RANGE/0.1/challenge";
const DST_CHALLENGE_H2S: &[u8] = b"DATE-RANGE/0.1/challenge-h2s";

/// Default holder policy: refuse ranges narrower than this many packed
/// slots (372 = one year), which would reveal the date in one request.
pub const DEFAULT_MIN_WINDOW: u64 = 372;

/// Request parameters: `ge` (born on or after) and/or `le` (born on or
/// before), both inclusive, as dates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateRangeParams {
    pub ge: Option<Ymd>,
    pub le: Option<Ymd>,
}

impl DateRangeParams {
    /// Born on or before `le` (YYYYMMDD).  Panics on invalid fields.
    pub fn le(le: u32) -> Self {
        DateRangeParams { ge: None, le: Some(Ymd::from_yyyymmdd(le).expect("valid YYYYMMDD")) }
    }
    /// Born on or after `ge` (YYYYMMDD).  Panics on invalid fields.
    pub fn ge(ge: u32) -> Self {
        DateRangeParams { ge: Some(Ymd::from_yyyymmdd(ge).expect("valid YYYYMMDD")), le: None }
    }
    /// Born between `ge` and `le` inclusive (YYYYMMDD).  Panics on invalid fields.
    pub fn between(ge: u32, le: u32) -> Self {
        DateRangeParams { ge: Self::ge(ge).ge, le: Self::le(le).le }
    }

    /// `u8 flags ‖ [u32 ge] ‖ [u32 le]` (§2).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.ge.is_some() as u8 | ((self.le.is_some() as u8) << 1));
        if let Some(d) = self.ge {
            w.u32(d.to_yyyymmdd());
        }
        if let Some(d) = self.le {
            w.u32(d.to_yyyymmdd());
        }
        w.into_bytes()
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        let bad = |s: &str| Error::Reject(format!("date-range: params: {s}"));
        let mut r = Reader::new(b, 9)?;
        let flags = r.u8()?;
        if !(1..=3).contains(&flags) {
            return Err(bad("flags"));
        }
        let mut date = || -> Result<Ymd> { Ymd::from_yyyymmdd(r.u32()?).ok_or_else(|| bad("date fields")) };
        let ge = if flags & 1 != 0 { Some(date()?) } else { None };
        let le = if flags & 2 != 0 { Some(date()?) } else { None };
        r.end()?;
        Ok(DateRangeParams { ge, le })
    }

    /// (lo, hi) for an attribute of `bits` bits; rejects lo ≥ hi.
    pub fn bounds(&self, bits: u16) -> Result<(u64, u64)> {
        let max = (1u64 << bits) - 1;
        let lo = self.ge.map_or(0, |d| d.pack());
        let hi = self.le.map_or(max, |d| d.pack().min(max));
        if lo >= hi {
            return Err(Error::Reject("date-range: params: empty or single-value range".into()));
        }
        Ok((lo, hi))
    }
}

impl std::fmt::Display for DateRangeParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.ge, self.le) {
            (Some(a), Some(b)) => write!(f, "born between {a} and {b}"),
            (Some(a), None) => write!(f, "born on or after {a}"),
            (None, Some(b)) => write!(f, "born on or before {b}"),
            (None, None) => write!(f, "no bound"),
        }
    }
}

/// Everything both sides derive from the request: the bounds and the bases.
struct Setup {
    lo: u64,
    hi: u64,
    bases: Bases,
}

fn setup(attr: &AttributeSpec, params: &[u8]) -> Result<Setup> {
    let bits = date::date_bits(attr)?;
    let p = DateRangeParams::decode(params)?;
    if p.encode() != params {
        return Err(Error::Reject("date-range: params: non-canonical".into()));
    }
    let (lo, hi) = p.bounds(bits)?;
    Ok(Setup { lo, hi, bases: Bases::new(hi - lo) })
}

/// C′ = D − lo·Y0.
fn statement(d: &G1Projective, lo: u64) -> Statement {
    Statement { c_prime: d - fixed::generators().y0.mul(&Scalar::from(lo)) }
}

/// The challenge function of §4 for one proof.
fn challenge_fn<'a>(
    env: &'a EnvContext,
    attr: &'a AttributeSpec,
    params: &'a [u8],
    su: &'a Setup,
    d: &'a G1Projective,
) -> impl Fn(&ChallengeInput) -> Result<Scalar> + 'a {
    move |ci: &ChallengeInput| {
        let tr = Transcript::new(DST_CHALLENGE)
            .add(b"plugin", PLUGIN_ID)
            .add(b"plugin_index", &env.plugin_index.to_be_bytes())
            .add(b"attribute", attr.name.as_bytes())
            .add(b"params", params)
            .add(b"env", &env.env_digest())
            .add(b"nonce", &env.nonce)
            .add(b"lo", &(su.lo as u32).to_be_bytes())
            .add(b"hi", &(su.hi as u32).to_be_bytes())
            .add(b"D", &point_to_octets_E1(d))
            .add(b"Di", ci.d)
            .add(b"A", ci.a)
            .add(b"B", ci.b)
            .into_bytes();
        Ok(hash_to_scalar(SUITE, &tr, DST_CHALLENGE_H2S)?.to_scalar()?)
    }
}

/// Holder side.  Stateless: everything is computed online (a few ms).
#[derive(Clone, Copy, Debug)]
pub struct DateRangeProver {
    /// Refuse ranges with fewer than this many packed slots (hi − lo + 1).
    pub min_window: u64,
}

impl Default for DateRangeProver {
    fn default() -> Self {
        DateRangeProver { min_window: DEFAULT_MIN_WINDOW }
    }
}

impl DateRangeProver {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_min_window(min_window: u64) -> Self {
        DateRangeProver { min_window }
    }
}

/// The committed value and opening of a one-message attribute.
fn value_and_opening(input: &CommittedInput) -> Result<(u64, Scalar, G1Projective)> {
    let [msg] = input.messages.as_slice() else {
        return Err(Error::Prover("date-range: expected one committed message".into()));
    };
    let m = scalar_to_u128(&msg.value)
        .and_then(|v| u64::try_from(v).ok())
        .ok_or_else(|| Error::Prover("date-range: committed value out of range".into()))?;
    Ok((m, msg.opening.to_scalar()?, msg.commitment))
}

impl PluginProver for DateRangeProver {
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
        let su = setup(&input.attribute, params).map_err(|e| Error::Prover(e.to_string()))?;
        if su.hi - su.lo + 1 < self.min_window {
            return Err(Error::Prover("date-range: requested window is narrower than the holder policy allows".into()));
        }
        let (m, s, d) = value_and_opening(input)?;
        if m < su.lo || m > su.hi {
            return Err(Error::Prover("date-range: the date is outside the requested range".into()));
        }
        let st = statement(&d, su.lo);
        let ch = challenge_fn(env, &input.attribute, params, &su, &d);
        range::prove(&st, &su.bases, m - su.lo, s, &ch, rng)
    }
}

/// Verifier side.
#[derive(Clone, Copy, Debug, Default)]
pub struct DateRangeVerifier;

impl PluginVerifier for DateRangeVerifier {
    fn plugin_id(&self) -> &[u8] {
        PLUGIN_ID
    }
    fn check_request(&self, attr: &AttributeSpec, params: &[u8]) -> Result<()> {
        setup(attr, params).map(|_| ())
    }
    fn verify(
        &self,
        env: &EnvContext,
        view: &CommittedView,
        params: &[u8],
        proof: &[u8],
        _rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>> {
        let su = setup(&view.attribute, params)?;
        let [d] = view.commitments.as_slice() else {
            return Err(Error::Reject("date-range: expected one commitment".into()));
        };
        let st = statement(d, su.lo);
        let ch = challenge_fn(env, &view.attribute, params, &su, d);
        range::verify(&st, &su.bases, proof, &ch)?;
        Ok(params.to_vec())
    }
}

/// Build the precomputed generator tables now (about 20 ms once per process,
/// [`fixed`]), for example at app start or when a request arrives, so the
/// first proof or verification does not pay for it.  Optional: the tables
/// are otherwise built on first use.
pub fn precompute() {
    fixed::generators();
}

/// Proof length for a request on an attribute (docs/plugins/DATE-RANGE.md §5).
pub fn proof_len(attr: &AttributeSpec, params: &[u8]) -> Result<usize> {
    Ok(range::proof_len(setup(attr, params)?.bases.k()))
}

/// DELIBERATELY UNSAFE proof construction for attack tests: arbitrary digits
/// and opening, no range or policy checks.  Never enable the feature in a
/// build you ship.
#[cfg(feature = "insecure-test-controls")]
pub mod insecure_test_controls {
    use super::*;

    /// What a malicious holder controls.
    pub struct Forge {
        /// One digit per base (any scalars); `None`: the low k bits of
        /// m − lo (mod r), as a cheating holder would try.
        pub digits: Option<Vec<Scalar>>,
        /// Added to the opening s before the last digit opening is solved,
        /// so the digit commitments no longer sum to C′.
        pub opening_offset: Scalar,
        /// Use these bounds in the statement instead of the request's
        /// (lo, hi), keeping the request's parameters in the transcript.
        pub bounds: Option<(u64, u64)>,
    }

    impl Default for Forge {
        fn default() -> Self {
            Forge { digits: None, opening_offset: Scalar::zero(), bounds: None }
        }
    }

    pub fn prove_forged(
        env: &EnvContext,
        input: &CommittedInput,
        params: &[u8],
        forge: Forge,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>> {
        let mut su = setup(&input.attribute, params)?;
        if let Some((lo, hi)) = forge.bounds {
            su.lo = lo;
            su.hi = hi;
            su.bases = Bases::new(hi - lo);
        }
        let (m, s, d) = value_and_opening(input)?;
        let k = su.bases.k();
        let digits = forge.digits.unwrap_or_else(|| {
            let v = m.wrapping_sub(su.lo);
            (0..k).map(|i| Scalar::from((v >> i) & 1)).collect()
        });
        let ch = challenge_fn(env, &input.attribute, params, &su, &d);
        range::prove_digits(&su.bases, &digits, s + forge.opening_offset, &ch, rng)
    }
}
