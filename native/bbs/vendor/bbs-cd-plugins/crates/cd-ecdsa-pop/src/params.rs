//! Plugin identifiers, request parameters and domain-separation tags.
use bbs_cd_plugin::codec::{Reader, Writer};
use bbs_cd_plugin::error::{Error, Result};
use cd_tom256::config::TransferConfig;

/// Plugin id (wire tag and transcript label).
pub const PLUGIN_ID: &[u8] = b"ecdsa-pop/0.1";
/// Attribute types of a committed P-256 device public key.  Both have the
/// `p256-point-xy` layout: 2k SCALAR limbs x_0..x_{k-1}, y_0..y_{k-1},
/// little-endian, each < 2^bits, bits ∈ {64, 96, 128}.  The type also fixes
/// the key's signing usage, attested at issuance (finding H-2): a key is
/// usable in exactly one mode, so the hashed-mode argument (EUF-CMA) never
/// has to account for a raw-signing interface on the same key, and the
/// raw-mode argument (KR-ECDSA) never for a hashing one.
///
/// Key usable only for ECDSA-P256-SHA256 (hashed mode).
pub const TYPE_P256_KEY_HASHED: &str = "p256-point-xy.ecdsa-sha256";
/// Key usable only for raw-representative ECDSA (raw mode).
pub const TYPE_P256_KEY_RAW: &str = "p256-point-xy.ecdsa-raw";

pub const PROFILE_SHARED_BIT: &[u8] = b"draft00-shared-bit";
pub const PROFILE_SEPARATE_PA: &[u8] = b"separate-pa";

pub fn is_known_profile(p: &[u8]) -> bool {
    p == PROFILE_SHARED_BIT || p == PROFILE_SEPARATE_PA
}

/// How the device signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Standard ECDSA-P256-SHA256 on a message bound to the request; the
    /// holder reveals the signature's nonce point K and proves ECDSA
    /// verification under the committed key.  Default.
    Hashed = 1,
    /// Raw signature on c·h under the randomized key Q′ = a·Q (c = a⁻¹); the
    /// proof of Q′ = a·Q is precomputed.  Feature `raw-mode`.
    Raw = 2,
}

impl Mode {
    /// The attribute type whose key may be used in this mode.
    pub fn key_type(self) -> &'static str {
        match self {
            Mode::Hashed => TYPE_P256_KEY_HASHED,
            Mode::Raw => TYPE_P256_KEY_RAW,
        }
    }

    /// The mode a key of attribute type `t` may be used in.
    pub fn for_key_type(t: &str) -> Option<Mode> {
        match t {
            TYPE_P256_KEY_HASHED => Some(Mode::Hashed),
            TYPE_P256_KEY_RAW => Some(Mode::Raw),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Mode::Hashed => "hashed",
            Mode::Raw => "raw",
        }
    }
}

/// The verifier's parameters for one `ecdsa-pop` request (bound into ctx).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EcdsaParams {
    pub mode: Mode,
    pub profile: Vec<u8>,
    pub transfer: TransferConfig,
}

impl EcdsaParams {
    /// Hashed mode, shared-bit profile, recommended transfer configuration.
    pub fn hashed(limb_bits: u8) -> Self {
        EcdsaParams {
            mode: Mode::Hashed,
            profile: PROFILE_SHARED_BIT.to_vec(),
            transfer: TransferConfig::recommended(limb_bits),
        }
    }

    /// Raw mode, shared-bit profile, recommended transfer configuration.
    pub fn raw(limb_bits: u8) -> Self {
        EcdsaParams {
            mode: Mode::Raw,
            profile: PROFILE_SHARED_BIT.to_vec(),
            transfer: TransferConfig::recommended(limb_bits),
        }
    }

    /// Canonical encoding: u8 mode ‖ u8-len profile ‖ R (1) ‖ b_c (2) ‖ b_f (2).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.mode as u8).var_u8(&self.profile).raw(&self.transfer.encode());
        w.into_bytes()
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b, 128)?;
        let mode = match r.u8()? {
            1 => Mode::Hashed,
            2 => Mode::Raw,
            _ => return Err(Error::Reject("ecdsa-pop: unknown mode".into())),
        };
        let profile = r.var_u8(64)?.to_vec();
        let transfer = TransferConfig { reps: r.u8()?, b_c: r.u16()?, b_f: r.u16()? };
        r.end()?;
        if !is_known_profile(&profile) {
            return Err(Error::Reject("ecdsa-pop: unknown profile".into()));
        }
        Ok(EcdsaParams { mode, profile, transfer })
    }
}

/// Domain-separation tags (all distinct, all distinct from the framework's).
pub const DST_STMT: &[u8] = b"ECDSA-POP/0.1/statement";
pub const DST_H_RAW: &[u8] = b"ECDSA-POP/0.1/raw-representative";
pub const DST_MSG: &[u8] = b"ECDSA-POP/0.1/device-message";
pub const DST_M_RAW: &[u8] = b"ECDSA-POP/0.1/raw-binding-challenge";
pub const DST_M_HASHED: &[u8] = b"ECDSA-POP/0.1/hashed-binding-challenge";
pub const DST_TR: &[u8] = b"ECDSA-POP/0.1/transfer-challenge";
pub const DST_SM: &[u8] = b"ECDSA-POP/0.1/sm-bits";
pub const DST_PA: &[u8] = b"ECDSA-POP/0.1/pa-challenge";
pub const DST_PA_H2F: &[u8] = b"ECDSA-POP/0.1/pa-challenge-h2f";
pub const DST_OC: &[u8] = b"ECDSA-POP/0.1/on-curve-challenge";
pub const DST_OC_H2F: &[u8] = b"ECDSA-POP/0.1/on-curve-challenge-h2f";
pub const DST_LINK: &[u8] = b"ECDSA-POP/0.1/link-challenge";
pub const DST_LINK_H2F: &[u8] = b"ECDSA-POP/0.1/link-challenge-h2f";
pub const DST_ATTEST: &[u8] = b"ECDSA-POP/0.1/device-attestation";

/// Proof magics.
pub const MAGIC_HASHED: &[u8; 4] = b"EPH\x01";
pub const MAGIC_RAW: &[u8; 4] = b"EPR\x01";
