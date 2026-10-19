//! Issuance of the device-key attributes (`p256-point-xy.ecdsa-sha256`,
//! `p256-point-xy.ecdsa-raw`): device-key attestation and the attribute
//! handler the issuer runs.
//!
//! [`Manufacturer`] is a simulation: it certifies device public keys and
//! their single permitted usage with a P-256 ECDSA signature over
//! DST ‖ policy ‖ usage ‖ device_pub.  It stands in for a real
//! key-attestation chain (Android Key Attestation, whose key description
//! lists the permitted digests; Apple App Attest).
//!
//! The handler enforces the issuance checks the soundness argument relies on
//! (DEVBIND decision D-1): the device key is a canonical, on-curve,
//! non-identity P-256 point accepted by the attestation policy, its attested
//! usage matches the attribute type (H-2), and the issuer computes the limbs
//! itself.
use bbs_cd::types::ScalarInput;
use bbs_cd_plugin::error::{Error, Result};
use bbs_cd_plugin::issuer::{scalar_from_u128, AttrHandler};
use bbs_cd_plugin::schema::ScalarsSpec;
use cd_tom256::config::{check_limb_bits, n_limbs};
use cd_tom256::p256x;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;

use crate::device::{HashSigner, SoftwareDevice};
use crate::params::{Mode, DST_ATTEST};

pub const POLICY_SOFTWARE: &[u8] = b"software-device-v0;";

pub struct Manufacturer {
    key: SigningKey,
}

impl Manufacturer {
    pub fn new() -> Self {
        Manufacturer { key: SigningKey::random(&mut OsRng) }
    }
    pub fn public_key(&self) -> [u8; 33] {
        self.key.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap()
    }
    /// Attestation: policy ‖ u8 usage ‖ signature.
    pub fn attest(&self, device_pub: &[u8; 33], usage: Mode) -> Vec<u8> {
        let msg = attested_message(device_pub, usage);
        let sig: Signature = self.key.sign(&msg);
        [POLICY_SOFTWARE, &[usage as u8], &sig.to_bytes()[..]].concat()
    }
    /// New software device whose key is usable only in `usage` mode, plus its
    /// attestation.
    pub fn provision(&self, usage: Mode, deterministic: bool) -> (SoftwareDevice, Vec<u8>) {
        let dev = SoftwareDevice::new(usage, deterministic);
        let att = self.attest(&dev.hash_public_key().unwrap(), usage);
        (dev, att)
    }
}

impl Default for Manufacturer {
    fn default() -> Self {
        Self::new()
    }
}

fn attested_message(device_pub: &[u8], usage: Mode) -> Vec<u8> {
    [DST_ATTEST, POLICY_SOFTWARE, &[usage as u8], device_pub].concat()
}

/// Whether `att` is a valid attestation by `manufacturer_pub` of `device_pub`
/// with the single permitted usage `usage`.
pub fn verify_attestation(manufacturer_pub: &[u8; 33], device_pub: &[u8], att: &[u8], usage: Mode) -> bool {
    let Some(rest) = att.strip_prefix(POLICY_SOFTWARE) else { return false };
    let Some((&u, sig)) = rest.split_first() else { return false };
    if u != usage as u8 {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_sec1_bytes(manufacturer_pub) else { return false };
    let Ok(sig) = Signature::from_slice(sig) else { return false };
    vk.verify(&attested_message(device_pub, usage), &sig).is_ok()
}

/// Issuance input of the attribute: the compressed device key followed by
/// its attestation.
pub fn key_input(device_pub: &[u8; 33], attestation: &[u8]) -> Vec<u8> {
    [&device_pub[..], attestation].concat()
}

/// Attribute handler for the device-key type of one usage
/// (`mode.key_type()`): checks the attestation (including the attested
/// usage) against the accepted manufacturers and the key, and returns the
/// limbs.  An issuer that offers both modes registers one handler per mode.
pub struct P256KeyHandler {
    pub manufacturers: Vec<[u8; 33]>,
    pub usage: Mode,
}

impl P256KeyHandler {
    pub fn new(manufacturers: Vec<[u8; 33]>, usage: Mode) -> Self {
        P256KeyHandler { manufacturers, usage }
    }
}

impl AttrHandler for P256KeyHandler {
    fn type_id(&self) -> &str {
        self.usage.key_type()
    }

    fn encode(&self, spec: &ScalarsSpec, input: &[u8]) -> Result<Vec<ScalarInput>> {
        let ty = self.usage.key_type();
        let refuse = |s: &str| Err(Error::Prover(format!("{ty}: {s}")));
        let bits: u8 = spec.bits.try_into().map_err(|_| Error::Prover(format!("{ty}: limb size")))?;
        check_limb_bits(bits).map_err(|e| Error::Prover(e.to_string()))?;
        if spec.count as usize != n_limbs(bits) {
            return refuse("limb count does not match the limb size");
        }
        if input.len() < 33 {
            return refuse("input");
        }
        let (device_pub, att) = input.split_at(33);
        let Ok(q) = p256x::decode_point(device_pub) else { return refuse("device key is not a canonical P-256 point") };
        if !self.manufacturers.iter().any(|m| verify_attestation(m, device_pub, att, self.usage)) {
            return refuse("attestation policy rejected device key or its usage");
        }
        Ok(p256x::limbs(&q, bits).into_iter().map(scalar_from_u128).collect())
    }
}
