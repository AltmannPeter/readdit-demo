//! P-256 signing device behind two adapters.
//!
//! * [`HashSigner`] (hashed mode): ordinary ECDSA-P256-SHA256 over a message.
//! * [`RawSigner`] (raw mode): signing of a 32-byte representative (ECDSA with
//!   e = OS2IP(rep) mod n, **no hashing**).  A key that answers raw requests
//!   signs any 32-byte value; use a dedicated key.
//!
//! [`SoftwareDevice`] keeps its key in a private field of an in-process object
//! (the Python prototype used a separate OS process); no real secure element.
//! Like a secure-element key policy (for example, the digest list of an
//! Android KeyMint key), each key has one fixed usage: a key created for
//! [`Mode::Hashed`] answers only [`HashSigner`] requests, a key created for
//! [`Mode::Raw`] only [`RawSigner`] requests (finding H-2).  The usage is
//! attested at issuance and fixed by the credential's attribute type.
use std::sync::Mutex;

use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier, RandomizedPrehashSigner};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::Scalar;
use rand_core::OsRng;

use bbs_cd_plugin::error::{Error, Result};

use crate::params::Mode;

pub trait RawSigner {
    fn public_key(&self) -> Result<[u8; 33]>;
    fn sign_representative(&self, rep: &[u8; 32]) -> Result<(Scalar, Scalar)>;
}

pub struct SoftwareDevice {
    key: Mutex<Option<SigningKey>>,
    pubkey: [u8; 33],
    usage: Mode,
    deterministic: bool,
    log: Mutex<Vec<[u8; 32]>>,
}

impl SoftwareDevice {
    /// Fresh random key generated inside the device object, usable only in
    /// `usage` mode.
    pub fn new(usage: Mode, deterministic: bool) -> Self {
        Self::from_key(SigningKey::random(&mut OsRng), usage, deterministic)
    }

    /// TEST/VECTOR ONLY: device with a caller-chosen key.
    pub fn from_key(key: SigningKey, usage: Mode, deterministic: bool) -> Self {
        let pubkey: [u8; 33] = key.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap();
        SoftwareDevice { key: Mutex::new(Some(key)), pubkey, usage, deterministic, log: Mutex::new(vec![]) }
    }

    /// The key's only permitted usage.
    pub fn usage(&self) -> Mode {
        self.usage
    }

    /// Withdraw access (models losing the device).
    pub fn revoke(&self) {
        *self.key.lock().unwrap() = None;
    }

    /// Representatives signed so far (call log kept by the adapter).
    pub fn log(&self) -> Vec<[u8; 32]> {
        self.log.lock().unwrap().clone()
    }
}

impl RawSigner for SoftwareDevice {
    fn public_key(&self) -> Result<[u8; 33]> {
        Ok(self.pubkey)
    }
    fn sign_representative(&self, rep: &[u8; 32]) -> Result<(Scalar, Scalar)> {
        if self.usage != Mode::Raw {
            return Err(Error::Prover("device: key policy does not allow raw signing".into()));
        }
        let guard = self.key.lock().unwrap();
        let key = guard.as_ref().ok_or(Error::DeviceUnavailable)?;
        self.log.lock().unwrap().push(*rep);
        let sig: Signature =
            if self.deterministic { key.sign_prehash(rep) } else { key.sign_prehash_with_rng(&mut OsRng, rep) }
                .map_err(|e| Error::Prover(format!("device: {e}")))?;
        let (r, s) = sig.split_scalars();
        Ok((*r, *s))
    }
}

/// Ordinary ECDSA verification on a 32-byte representative.
pub fn ecdsa_verify_prehashed(pub33: &[u8; 33], rep: &[u8; 32], r: &Scalar, s: &Scalar) -> bool {
    let Ok(vk) = VerifyingKey::from_sec1_bytes(pub33) else { return false };
    let Ok(sig) = Signature::from_scalars(r.to_bytes(), s.to_bytes()) else { return false };
    vk.verify_prehash(rep, &sig).is_ok()
}

/// An ordinary hashing ECDSA signer, ECDSA-P256-SHA256 over a message.  This
/// is the only interface the hashed mode needs; the same key must not also
/// be reachable through raw signing (H-2).
pub trait HashSigner {
    fn hash_public_key(&self) -> Result<[u8; 33]>;
    fn sign_message(&self, msg: &[u8]) -> Result<(Scalar, Scalar)>;
}

impl HashSigner for SoftwareDevice {
    fn hash_public_key(&self) -> Result<[u8; 33]> {
        Ok(self.pubkey)
    }
    fn sign_message(&self, msg: &[u8]) -> Result<(Scalar, Scalar)> {
        use p256::ecdsa::signature::{RandomizedSigner, Signer};
        if self.usage != Mode::Hashed {
            return Err(Error::Prover("device: key policy does not allow hashed signing".into()));
        }
        let guard = self.key.lock().unwrap();
        let key = guard.as_ref().ok_or(Error::DeviceUnavailable)?;
        let sig: Signature = if self.deterministic { key.sign(msg) } else { key.sign_with_rng(&mut OsRng, msg) };
        let (r, s) = sig.split_scalars();
        Ok((*r, *s))
    }
}
