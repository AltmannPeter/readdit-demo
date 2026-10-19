//! `pseudonym`: a per-relying-party pseudonym from a committed seed (plugin of
//! `bbs-cd-plugin`).
//!
//! The credential holds a seed as a `nym-seed.issuer-known` attribute (one
//! scalar).  The verifier asks for a pseudonym under a configuration and a
//! relying-party identifier; the holder commits to the seed in the BBS
//! presentation, reveals nym = seed·OP with OP = hash_to_curve(config ‖
//! relying party) and proves that nym was computed from the signed seed.
//!
//! Version 0.1 has one configuration, [`CONFIG_KNOWN_OFFENDER_MATCHING_SSC`]:
//! the issuer-known seed (the issuer can map a pseudonym back to the
//! person), no prover input, and the relying party's identifier, which the
//! wallet takes from the relying party's access certificate.
//!
//! Specification: `docs/plugins/PSEUDONYM.md`.
//! **Not constant-time. Not audited. Not for production.**
#![forbid(unsafe_code)]
#![allow(non_snake_case)]

use bbs_cd::helpers::msm_vartime;
use bbs_cd::primitives::{
    decode_G1, hash_to_curve_g1, point_to_octets_E1, scalar_from_octets, scalar_from_wide, scalar_to_octets,
};
use bbs_cd::types::ScalarInput;
use bbs_cd::utils::{commitment_generators, hash_to_scalar};
use bbs_cd_plugin::codec::{Reader, Writer};
use bbs_cd_plugin::error::{Error, Result};
use bbs_cd_plugin::issuer::{AttrHandler, SUITE};
use bbs_cd_plugin::plugin::{CommittedInput, CommittedView, CryptoRngCore, EnvContext, PluginProver, PluginVerifier};
use bbs_cd_plugin::schema::{AttributeSpec, ScalarsSpec};
use bbs_cd_plugin::transcript::Transcript;
use bls12_381::{G1Projective, Scalar};
use rand_core::{CryptoRng, RngCore};

pub const PLUGIN_ID: &[u8] = b"pseudonym/0.1";
/// Seed attribute type: one scalar, known to the issuer.
pub const TYPE_NYM_SEED_ISSUER_KNOWN: &str = "nym-seed.issuer-known";
/// Configuration: issuer-known seed, no prover input, relying-party identifier.
pub const CONFIG_KNOWN_OFFENDER_MATCHING_SSC: &str = "known-offender-matching-ssc";
/// Supported configurations (0.1).
pub const CONFIGS: &[&str] = &[CONFIG_KNOWN_OFFENDER_MATCHING_SSC];

const DST_OP: &[u8] = b"BBS-CD-PLUGINS/0.1/PSEUDONYM/OP";
const DST_CHALLENGE: &[u8] = b"PSEUDONYM/0.1/challenge";
const DST_CHALLENGE_H2S: &[u8] = b"PSEUDONYM/0.1/challenge-h2s";
/// Proof magic.
pub const MAGIC: &[u8; 4] = b"PSN\x01";
/// Proof length: magic ‖ nym ‖ c ‖ z_m ‖ z_s.
pub const PROOF_LEN: usize = 4 + 48 + 3 * 32;
/// Longest relying-party identifier.
pub const MAX_VERIFIER_INPUT: usize = 255;

fn rej(s: &str) -> Error {
    Error::Reject(format!("pseudonym: {s}"))
}

// ---------------------------------------------------------------- seed

/// A fresh random seed (32 bytes big-endian, a nonzero scalar), for the
/// issuer to keep on record and pass to [`NymSeedHandler`].
pub fn new_seed<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> [u8; 32] {
    loop {
        let mut w = [0u8; 64];
        rng.fill_bytes(&mut w);
        let s = Scalar::from_bytes_wide(&w);
        if s != Scalar::zero() {
            return scalar_to_octets(&s);
        }
    }
}

fn seed_scalar(seed: &[u8]) -> Option<Scalar> {
    scalar_from_octets(seed).ok().filter(|s| *s != Scalar::zero())
}

/// Issuance handler for `nym-seed.issuer-known`: the input is the seed, 32
/// bytes big-endian, a canonical nonzero scalar.
pub struct NymSeedHandler;

impl AttrHandler for NymSeedHandler {
    fn type_id(&self) -> &str {
        TYPE_NYM_SEED_ISSUER_KNOWN
    }
    fn encode(&self, spec: &ScalarsSpec, input: &[u8]) -> Result<Vec<ScalarInput>> {
        if spec.count != 1 || spec.bits != 255 {
            return Err(Error::Prover(format!("{TYPE_NYM_SEED_ISSUER_KNOWN}: layout must be one 255-bit scalar")));
        }
        let s = (input.len() == 32)
            .then(|| seed_scalar(input))
            .flatten()
            .ok_or_else(|| Error::Prover(format!("{TYPE_NYM_SEED_ISSUER_KNOWN}: not a nonzero 32-byte scalar")))?;
        Ok(vec![ScalarInput::from(s)])
    }
}

fn check_attribute(attr: &AttributeSpec) -> Result<()> {
    match attr.scalars_spec() {
        Some(s) if s.type_id == TYPE_NYM_SEED_ISSUER_KNOWN && s.count == 1 && s.bits == 255 => Ok(()),
        _ => Err(rej(&format!("attribute {} is not a {TYPE_NYM_SEED_ISSUER_KNOWN} attribute", attr.name))),
    }
}

// ---------------------------------------------------------------- params

/// Request parameters: the pseudonym configuration and the relying party's
/// identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PseudonymParams {
    pub config: String,
    pub verifier_input: Vec<u8>,
}

impl PseudonymParams {
    /// `known-offender-matching-ssc` for the relying party `verifier_id`.
    pub fn known_offender_matching(verifier_id: &[u8]) -> Self {
        PseudonymParams { config: CONFIG_KNOWN_OFFENDER_MATCHING_SSC.into(), verifier_input: verifier_id.to_vec() }
    }

    /// `u8-len config_id ‖ u8-len verifier_input`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.var_u8(self.config.as_bytes()).var_u8(&self.verifier_input);
        w.into_bytes()
    }

    /// Strict decoding and the 0.1 checks (known configuration, identifier
    /// of 1 to 255 bytes).
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b, 2 + 255 + MAX_VERIFIER_INPUT)?;
        let config = String::from_utf8(r.var_u8(255)?.to_vec()).map_err(|_| rej("params: configuration"))?;
        let verifier_input = r.var_u8(MAX_VERIFIER_INPUT)?.to_vec();
        r.end()?;
        if !CONFIGS.contains(&config.as_str()) {
            return Err(rej(&format!("params: unsupported configuration {config:?}")));
        }
        if verifier_input.is_empty() {
            return Err(rej("params: empty verifier input"));
        }
        Ok(PseudonymParams { config, verifier_input })
    }

    /// OP = hash_to_curve_g1(u8(len(config)) ‖ config ‖ verifier_input).
    pub fn op(&self) -> Result<G1Projective> {
        let msg = [&[self.config.len() as u8][..], self.config.as_bytes(), &self.verifier_input].concat();
        Ok(hash_to_curve_g1(SUITE, &msg, DST_OP)?)
    }
}

/// The pseudonym of `seed` under `params` (48 bytes): what the issuer, which
/// knows the seed, computes to map a pseudonym back to a person.
pub fn pseudonym_for(seed: &[u8; 32], params: &PseudonymParams) -> Result<[u8; 48]> {
    let s = seed_scalar(seed).ok_or_else(|| rej("seed"))?;
    Ok(point_to_octets_E1(&(params.op()? * s)))
}

// ---------------------------------------------------------------- proof

fn setup(attr: &AttributeSpec, params: &[u8]) -> Result<(PseudonymParams, G1Projective)> {
    check_attribute(attr)?;
    let p = PseudonymParams::decode(params)?;
    let op = p.op()?;
    Ok((p, op))
}

#[allow(clippy::too_many_arguments)]
fn challenge(
    env: &EnvContext,
    attr: &AttributeSpec,
    params: &[u8],
    d: &G1Projective,
    nym: &[u8],
    t1: &G1Projective,
    t2: &G1Projective,
) -> Result<Scalar> {
    let tr = Transcript::new(DST_CHALLENGE)
        .add(b"plugin", PLUGIN_ID)
        .add(b"plugin_index", &env.plugin_index.to_be_bytes())
        .add(b"attribute", attr.name.as_bytes())
        .add(b"params", params)
        .add(b"env", &env.env_digest())
        .add(b"nonce", &env.nonce)
        .add(b"D", &point_to_octets_E1(d))
        .add(b"nym", nym)
        .add(b"T1", &point_to_octets_E1(t1))
        .add(b"T2", &point_to_octets_E1(t2))
        .into_bytes();
    Ok(hash_to_scalar(SUITE, &tr, DST_CHALLENGE_H2S)?.to_scalar()?)
}

fn rand_scalar(rng: &mut dyn CryptoRngCore) -> Scalar {
    let mut w = [0u8; 48];
    rng.fill_bytes(&mut w);
    scalar_from_wide(&w)
}

/// The proof for witnesses (m, s): `nym_seed` is the seed the pseudonym is
/// computed from and `op` its base; honest inputs have nym_seed = m and the
/// requested OP.
#[allow(clippy::too_many_arguments)]
fn prove_with(
    env: &EnvContext,
    attr: &AttributeSpec,
    params: &[u8],
    d: &G1Projective,
    m: Scalar,
    s: Scalar,
    nym_point: G1Projective,
    op: G1Projective,
    rng: &mut dyn CryptoRngCore,
) -> Result<Vec<u8>> {
    let (y0, y1) = commitment_generators(SUITE, &SUITE.api_id())?;
    let nym = point_to_octets_E1(&nym_point);
    let (a, b) = (rand_scalar(rng), rand_scalar(rng));
    let t1 = msm_vartime(&[y0, y1], &[a, b]);
    let t2 = op * a;
    let c = challenge(env, attr, params, d, &nym, &t1, &t2)?;
    Ok([&MAGIC[..], &nym, &scalar_to_octets(&c), &scalar_to_octets(&(a + c * m)), &scalar_to_octets(&(b + c * s))]
        .concat())
}

fn seed_and_opening(input: &CommittedInput) -> Result<(Scalar, Scalar, G1Projective)> {
    let [msg] = input.messages.as_slice() else {
        return Err(Error::Prover("pseudonym: expected one committed message".into()));
    };
    Ok((msg.value.to_scalar()?, msg.opening.to_scalar()?, msg.commitment))
}

/// Holder side.  Created with the relying-party identifier the wallet took
/// from the relying party's access certificate; refuses a request for any
/// other identifier (docs/plugins/PSEUDONYM.md §7).
#[derive(Clone, Debug)]
pub struct PseudonymProver {
    pub verifier_id: Vec<u8>,
}

impl PseudonymProver {
    pub fn new(verifier_id: &[u8]) -> Self {
        PseudonymProver { verifier_id: verifier_id.to_vec() }
    }
}

impl PluginProver for PseudonymProver {
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
        let (p, op) = setup(&input.attribute, params).map_err(|e| Error::Prover(e.to_string()))?;
        if p.verifier_input != self.verifier_id {
            return Err(Error::Prover("pseudonym: requested relying party differs from the access certificate".into()));
        }
        let (m, s, d) = seed_and_opening(input)?;
        if m == Scalar::zero() {
            return Err(Error::Prover("pseudonym: zero seed".into()));
        }
        prove_with(env, &input.attribute, params, &d, m, s, op * m, op, rng)
    }
}

/// Verifier side.  `for_verifier(id)` also refuses requests for any
/// relying-party identifier other than `id`.
#[derive(Clone, Debug, Default)]
pub struct PseudonymVerifier {
    pub own_id: Option<Vec<u8>>,
}

impl PseudonymVerifier {
    /// Accepts any relying-party identifier (for example an intermediary).
    pub fn any() -> Self {
        Self::default()
    }
    /// Accepts only requests for the relying party `id`.
    pub fn for_verifier(id: &[u8]) -> Self {
        PseudonymVerifier { own_id: Some(id.to_vec()) }
    }
}

impl PluginVerifier for PseudonymVerifier {
    fn plugin_id(&self) -> &[u8] {
        PLUGIN_ID
    }
    fn check_request(&self, attr: &AttributeSpec, params: &[u8]) -> Result<()> {
        let (p, _) = setup(attr, params)?;
        if p.encode() != params {
            return Err(rej("params: non-canonical"));
        }
        match &self.own_id {
            Some(id) if *id != p.verifier_input => Err(rej("request for another relying party")),
            _ => Ok(()),
        }
    }
    fn verify(
        &self,
        env: &EnvContext,
        view: &CommittedView,
        params: &[u8],
        proof: &[u8],
        _rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>> {
        self.check_request(&view.attribute, params)?;
        let (_, op) = setup(&view.attribute, params)?;
        let [d] = view.commitments.as_slice() else {
            return Err(rej("expected one commitment"));
        };
        if proof.len() != PROOF_LEN {
            return Err(Error::Decode("pseudonym: proof length".into()));
        }
        let mut r = Reader::new(proof, PROOF_LEN)?;
        if r.take(4)? != MAGIC {
            return Err(Error::Decode("pseudonym: magic".into()));
        }
        let nym_bytes = r.take(48)?;
        let nym = decode_G1(nym_bytes, false).map_err(|_| Error::Decode("pseudonym: nym".into()))?;
        let sc = |b: &[u8]| scalar_from_octets(b).map_err(|_| Error::Decode("pseudonym: scalar".into()));
        let (c, zm, zs) = (sc(r.take(32)?)?, sc(r.take(32)?)?, sc(r.take(32)?)?);
        r.end()?;
        let (y0, y1) = commitment_generators(SUITE, &SUITE.api_id())?;
        let t1 = msm_vartime(&[y0, y1, *d], &[zm, zs, -c]);
        let t2 = msm_vartime(&[op, nym], &[zm, -c]);
        if challenge(env, &view.attribute, params, d, nym_bytes, &t1, &t2)? != c {
            return Err(rej("proof"));
        }
        Ok(nym_bytes.to_vec())
    }
}

/// DELIBERATELY UNSAFE proof construction for attack tests.  Never enable
/// the feature in a build you ship.
#[cfg(feature = "insecure-test-controls")]
pub mod insecure_test_controls {
    use super::*;

    /// What a malicious holder controls.
    #[derive(Default)]
    pub struct Forge {
        /// Compute the pseudonym from this seed (responses still use the
        /// committed seed).
        pub nym_seed: Option<Scalar>,
        /// Use this seed everywhere: pseudonym and responses.
        pub witness_seed: Option<Scalar>,
        /// Compute OP from this relying-party identifier instead of the
        /// requested one (the parameters in the transcript are unchanged).
        pub verifier_input: Option<Vec<u8>>,
        /// Present the identity point as the pseudonym.
        pub identity_nym: bool,
    }

    pub fn prove_forged(
        env: &EnvContext,
        input: &CommittedInput,
        params: &[u8],
        forge: Forge,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>> {
        let (mut p, _) = setup(&input.attribute, params)?;
        if let Some(v) = forge.verifier_input {
            p.verifier_input = v;
        }
        let op = p.op()?;
        let (m, s, d) = seed_and_opening(input)?;
        let m = forge.witness_seed.unwrap_or(m);
        let nym = if forge.identity_nym { G1Projective::identity() } else { op * forge.nym_seed.unwrap_or(m) };
        prove_with(env, &input.attribute, params, &d, m, s, nym, op, rng)
    }
}
