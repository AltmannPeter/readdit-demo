//! Spec 3.1–3.2; BBS-12 7.2: fixed ciphersuite parameters.
use crate::primitives::decode_G1;
use bls12_381::{G1Projective, G2Projective};
pub const R: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];
pub const MAX_MESSAGES: u128 = (u64::MAX as u128) - 1;
pub const EXPAND_LEN: usize = 48;
pub const OCTET_POINT_LENGTH: usize = 48;
pub const OCTET_SCALAR_LENGTH: usize = 32;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ciphersuite {
    Sha256,
    Shake256,
}
impl Ciphersuite {
    /// Spec 3.1: exact BBS-12 ciphersuite identifiers.
    pub fn ciphersuite_id(self) -> &'static [u8] {
        match self {
            Self::Sha256 => b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_",
            Self::Shake256 => b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_",
        }
    }
    /// Spec 3.2: profile mixed-message interface identifier.
    pub fn api_id(self) -> Vec<u8> {
        [self.ciphersuite_id(), b"H2G_HM2S_S2S_"].concat()
    }
    /// BBS-12 3.5: identifier for BBS core cross-checks.
    pub fn bbs_api_id(self) -> Vec<u8> {
        [self.ciphersuite_id(), b"H2G_HM2S_"].concat()
    }
    /// Spec 1.5.2 / BBS-12 7.2.1–7.2.2: fixed P1, not BP1.
    pub fn P1(self) -> G1Projective {
        let hex = match self {
            Self::Sha256 => {
                "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9"
            }
            Self::Shake256 => {
                "8929dfbc7e6642c4ed9cba0856e493f8b9d7d5fcb0c31ef8fdcd34d50648a56c795e106e9eada6e0bda386b414150755"
            }
        };
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("fixed P1 hex"))
            .collect();
        decode_G1(&bytes, false).expect("BBS-12 fixed P1 is a nonidentity subgroup point")
    }
}
/// Spec 1.5.2 / BBS-12 Appendix B.1: public-key base point.
pub fn BP2() -> G2Projective {
    G2Projective::generator()
}
