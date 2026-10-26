//! Limb layout of a committed P-256 point and transfer configuration.
//!
//! * The **limb size** b_x is chosen by the issuer and fixed by the credential
//!   schema (layout `p256-point-xy`, `bits` = b_x).  Each P-256
//!   coordinate (< p < 2^256) is split little-endian into k = ⌈256 / b_x⌉
//!   limbs; the attribute holds the k x-limbs followed by the k y-limbs as
//!   consecutive SCALAR messages.
//! * The **transfer configuration** (repetitions R, challenge bits b_c, abort
//!   slack b_f) is chosen by the verifier and bound into the request context.
//!   It is never read from a presentation.
//!
//! Constraints (enforced by `TransferConfig::validate`):
//!   b_x + b_c + b_f ≤ 254   (integer response z < 2^254 < ℓ, no wraparound)
//!   R · b_c ≥ 128          (no component weaker than BLS12-381)
use crate::params::{MAX_Z_BITS, MIN_SECURITY_BITS};
use bbs_cd_plugin::error::{Error, Result};

/// Limb sizes an issuer may choose.
pub const ALLOWED_LIMB_BITS: [u8; 3] = [64, 96, 128];
/// Default limb size (decision D6).
pub const DEFAULT_LIMB_BITS: u8 = 96;

pub fn check_limb_bits(b: u8) -> Result<()> {
    if ALLOWED_LIMB_BITS.contains(&b) {
        Ok(())
    } else {
        Err(Error::Decode(format!("unsupported limb size {b}")))
    }
}

/// Limbs per coordinate.
pub fn limbs_per_coord(limb_bits: u8) -> usize {
    256usize.div_ceil(limb_bits as usize)
}

/// Total key limbs in a credential (x limbs then y limbs).
pub fn n_limbs(limb_bits: u8) -> usize {
    2 * limbs_per_coord(limb_bits)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransferConfig {
    /// Independent repetitions per limb.
    pub reps: u8,
    /// Challenge bits per repetition (multiple of 8).
    pub b_c: u16,
    /// Abort slack: each transfer aborts with probability 2^-b_f.
    pub b_f: u16,
}

impl TransferConfig {
    /// Default for 64- and 96-bit limbs (decision D6).
    pub const DEFAULT: TransferConfig = TransferConfig { reps: 1, b_c: 128, b_f: 16 };
    /// Named alternative for 128-bit limbs: HPI parameters, two repetitions.
    pub const L128_R2: TransferConfig = TransferConfig { reps: 2, b_c: 112, b_f: 8 };

    /// Recommended configuration for an issuer's limb size.
    pub fn recommended(limb_bits: u8) -> TransferConfig {
        if limb_bits <= 96 {
            Self::DEFAULT
        } else {
            Self::L128_R2
        }
    }

    pub fn validate(&self, limb_bits: u8) -> Result<()> {
        let rej = |s: String| Err(Error::Reject(format!("transfer config: {s}")));
        check_limb_bits(limb_bits)?;
        if !(1..=4).contains(&self.reps) {
            return rej("repetitions must be in [1, 4]".into());
        }
        if self.b_c % 8 != 0 || !(64..=128).contains(&self.b_c) {
            return rej("b_c must be a multiple of 8 in [64, 128]".into());
        }
        if !(8..=32).contains(&self.b_f) {
            return rej("b_f must be in [8, 32]".into());
        }
        let z_bits = limb_bits as u32 + self.b_c as u32 + self.b_f as u32;
        if z_bits > MAX_Z_BITS {
            return rej(format!("b_x + b_c + b_f = {z_bits} > {MAX_Z_BITS}"));
        }
        if (self.reps as u32) * (self.b_c as u32) < MIN_SECURITY_BITS {
            return rej(format!("R * b_c < {MIN_SECURITY_BITS}"));
        }
        Ok(())
    }

    pub fn z_bits(&self, limb_bits: u8) -> u32 {
        limb_bits as u32 + self.b_c as u32 + self.b_f as u32
    }

    pub fn z_bytes(&self, limb_bits: u8) -> usize {
        (self.z_bits(limb_bits) as usize).div_ceil(8)
    }

    /// Canonical encoding: I2OSP(R,1) ‖ I2OSP(b_c,2) ‖ I2OSP(b_f,2).
    pub fn encode(&self) -> [u8; 5] {
        let mut o = [0u8; 5];
        o[0] = self.reps;
        o[1..3].copy_from_slice(&self.b_c.to_be_bytes());
        o[3..5].copy_from_slice(&self.b_f.to_be_bytes());
        o
    }
}
