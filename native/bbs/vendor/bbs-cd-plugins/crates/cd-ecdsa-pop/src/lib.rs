//! `ecdsa-pop`: proof of possession of a P-256 device key committed in an
//! ETSI BBS committed-disclosure credential (plugin of `bbs-cd-plugin`).
//!
//! The credential holds the device key as a device-key attribute (2k SCALAR
//! limbs, layout `p256-point-xy`).  Its type fixes the key's one permitted
//! signing mode: `p256-point-xy.ecdsa-sha256` (hashed) or
//! `p256-point-xy.ecdsa-raw` (raw); a request for the other mode is refused.
//! The verifier asks for an `ecdsa-pop` proof on that attribute; the
//! presentation then commits to the limbs (ETSI D_j) and the plugin proves
//! that the committed key signed this request.
//!
//! * **Hashed mode** (default): standard ECDSA-P256-SHA256 by the device; the
//!   holder proves ECDSA verification under the committed key.  Rests on
//!   ECDSA unforgeability.
//! * **Raw mode** (feature `raw-mode`): raw signature on c·h under the
//!   randomized key Q′ = a·Q; the proof is precomputed.  Rests on KR-ECDSA and
//!   needs raw-digest signing from the secure element.
//!
//! Specification: `docs/plugins/ECDSA-POP.md`.
//! **Not constant-time. Not audited. Not for production.**
#![forbid(unsafe_code)]
#![allow(non_snake_case)]

use std::cell::RefCell;
use std::time::Duration;

use bbs_cd_plugin::error::{Error, Result};
use bbs_cd_plugin::par::Parallelism;
use bbs_cd_plugin::plugin::{CommittedInput, CommittedView, CryptoRngCore, EnvContext, PluginProver, PluginVerifier};
use bbs_cd_plugin::schema::AttributeSpec;
use rand_core::{CryptoRng, RngCore};

pub mod attestation;
pub mod common;
pub mod device;
pub mod hashed;
pub mod params;
#[cfg(feature = "raw-mode")]
pub mod raw;

pub use common::VerifyMode;
pub use device::{HashSigner, RawSigner, SoftwareDevice};
pub use params::{EcdsaParams, Mode, PLUGIN_ID, TYPE_P256_KEY_HASHED, TYPE_P256_KEY_RAW};

/// Prover timings of one proof.
#[derive(Clone, Debug, Default)]
pub struct ProveStats {
    /// Statement and representative, before the device call.
    pub pre_sign: Duration,
    pub device_sign: Duration,
    /// Everything after the device returns (proofs that depend on the
    /// signature, responses, encoding).
    pub post_sign: Duration,
    pub transfer_attempts: usize,
    pub sign_attempts: usize,
    pub bytes: usize,
}

/// Prepared (offline) plugin state for one expected request policy.
#[allow(clippy::large_enum_variant)] // moved once, consumed by `prove`
pub enum EcdsaSlot {
    Hashed(hashed::HashedSlot),
    #[cfg(feature = "raw-mode")]
    Raw(raw::RawSlot),
}

/// Offline preparation from the committed key limbs (see
/// `CredentialSlot::committed_input`).  `spare_sets` extra transfer sets
/// absorb the (2^-b_f per entry) transfer aborts.
pub fn prepare<R: RngCore + CryptoRng>(
    input: &CommittedInput,
    params: &EcdsaParams,
    spare_sets: usize,
    par: Parallelism,
    rng: &mut R,
) -> Result<EcdsaSlot> {
    match params.mode {
        Mode::Hashed => Ok(EcdsaSlot::Hashed(hashed::prepare(input, params, spare_sets, par, rng)?)),
        #[cfg(feature = "raw-mode")]
        Mode::Raw => Ok(EcdsaSlot::Raw(raw::prepare(input, params, spare_sets, None, par, rng)?)),
        #[cfg(not(feature = "raw-mode"))]
        Mode::Raw => Err(Error::Prover("ecdsa-pop: raw mode needs the raw-mode feature".into())),
    }
}

/// The signing device, by mode.
#[derive(Clone, Copy)]
pub enum Signer<'a> {
    Hash(&'a dyn HashSigner),
    #[cfg(feature = "raw-mode")]
    Raw(&'a dyn RawSigner),
}

/// Prover for one `ecdsa-pop` request.  Consumed by the envelope.
pub struct EcdsaPopProver<'a> {
    pub slot: EcdsaSlot,
    pub signer: Signer<'a>,
    /// Fixed salt nh (tests/vectors); `None` draws a fresh one.
    pub nh: Option<[u8; 32]>,
    pub parallelism: Parallelism,
    /// Receives the prover timings.
    pub stats: Option<&'a RefCell<ProveStats>>,
}

impl<'a> EcdsaPopProver<'a> {
    pub fn new(slot: EcdsaSlot, signer: Signer<'a>) -> Self {
        EcdsaPopProver { slot, signer, nh: None, parallelism: Parallelism::Off, stats: None }
    }
}

impl PluginProver for EcdsaPopProver<'_> {
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
        let mut st = ProveStats::default();
        let out = match (self.slot, self.signer) {
            (EcdsaSlot::Hashed(s), Signer::Hash(sig)) => {
                hashed::prove(s, env, input, params, sig, self.nh, self.parallelism, &mut r, Some(&mut st))?
            }
            #[cfg(feature = "raw-mode")]
            (EcdsaSlot::Raw(s), Signer::Raw(sig)) => raw::prove_impl(
                s,
                env,
                input,
                params,
                sig,
                raw::HMode::Candidate,
                true,
                self.nh,
                &mut r,
                Some(&mut st),
            )?,
            #[cfg(feature = "raw-mode")]
            _ => return Err(Error::Prover("ecdsa-pop: signer does not match the slot's mode".into())),
        };
        if let Some(cell) = self.stats {
            *cell.borrow_mut() = st;
        }
        Ok(out)
    }
}

/// Verifier of `ecdsa-pop` proofs.
#[derive(Clone, Debug)]
pub struct EcdsaPopVerifier {
    pub parallelism: Parallelism,
    pub verify_mode: VerifyMode,
    /// Accept raw-mode requests (only with the `raw-mode` feature).
    pub allow_raw: bool,
}

impl Default for EcdsaPopVerifier {
    fn default() -> Self {
        EcdsaPopVerifier {
            parallelism: Parallelism::Off,
            verify_mode: VerifyMode::Batch,
            allow_raw: cfg!(feature = "raw-mode"),
        }
    }
}

impl EcdsaPopVerifier {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PluginVerifier for EcdsaPopVerifier {
    fn plugin_id(&self) -> &[u8] {
        PLUGIN_ID
    }

    fn check_request(&self, attr: &AttributeSpec, params: &[u8]) -> Result<()> {
        let p = EcdsaParams::decode(params)?;
        if p.encode() != params {
            return Err(Error::Reject("ecdsa-pop: non-canonical parameters".into()));
        }
        common::check_params(attr, &p)?;
        if p.mode == Mode::Raw && !(cfg!(feature = "raw-mode") && self.allow_raw) {
            return Err(Error::Reject("ecdsa-pop: raw mode not accepted".into()));
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
        self.check_request(&view.attribute, params)?;
        let p = EcdsaParams::decode(params)?;
        let mut r = rng;
        match p.mode {
            Mode::Hashed => {
                hashed::verify(env, view, params, &p, proof, self.verify_mode, self.parallelism, &mut r)?;
            }
            #[cfg(feature = "raw-mode")]
            Mode::Raw => {
                raw::verify_impl(
                    env,
                    view,
                    params,
                    &p,
                    proof,
                    raw::HMode::Candidate,
                    self.verify_mode,
                    self.parallelism,
                    &mut r,
                )?;
            }
            #[cfg(not(feature = "raw-mode"))]
            Mode::Raw => return Err(Error::Reject("ecdsa-pop: raw mode not accepted".into())),
        }
        Ok(vec![])
    }
}
