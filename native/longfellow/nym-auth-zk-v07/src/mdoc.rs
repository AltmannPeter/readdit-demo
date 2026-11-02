//! The holder's credential: an ISO/IEC 18013-5 IssuerSigned structure of the nym_auth attestation
//! (docType `eu.europa.ec.eudi.nym_auth.1`) in the layout of **rulebook v0.7**.
//!
//! The MSO's `valueDigests` (namespace `eu.nym_auth.v1`) hold the commitments themselves:
//! digestID 0 is `bsc = AES-128(secret_seed, "nym/b" || 01 || birth_date) ||
//! AES-128(secret_seed, "nym/b" || 02 || 0^10)` and digestID 1 is `psc` (two AES-128 blocks under
//! the holder's private_seed, or 32 zero bytes). The device key is compressed (COSE_Key `-3` a
//! bool). There are no IssuerSignedItems and no `nameSpaces`. The MSO is exactly 350 bytes in a
//! fixed key order, so the COSE Sig_structure is exactly 375 bytes (6 SHA-256 blocks once padded)
//! and every field sits at a fixed offset ([`TEMPLATE`], [`FIELDS`]).
//!
//! The credential must be exactly:
//!
//! ```text
//! a1 6a "issuerAuth"                       IssuerSigned: { "issuerAuth": COSE_Sign1 }
//!   84                                     COSE_Sign1 [
//!     43 a1 01 26                            protected: { 1: -7 } (ES256)
//!     a1 18 21 <bstr x5chain>                unprotected: { 33: x5chain } (one certificate)
//!     59 01 63 d8 18 59 01 5e <MSO, 350>     payload: tag 24 on the 350-byte MSO
//!     58 40 <r || s>                         signature ]
//! ```
//!
//! and the Sig_structure built from it must equal [`TEMPLATE`] at every byte outside the seven
//! private fields, whose three tdates must read `YYYY-MM-DDThh:mm:ssZ` and whose sign byte must be
//! `f4` or `f5`. Anything else is refused before proving ([`parse`]); the hash circuit checks the
//! same bytes again (they are its constants).

use crate::Error;

pub const DOC_TYPE: &str = "eu.europa.ec.eudi.nym_auth.1";
pub const NAMESPACE: &str = "eu.nym_auth.v1";

/// The Sig_structure's length, and its SHA-256 blocks once padded.
pub const SIG_STRUCTURE_LEN: usize = 375;
pub const SIGNED_BLOCKS: usize = 6;
/// The MSO's length.
pub const MSO_LEN: usize = 350;

/// The Sig_structure template: every constant byte of the layout, the private fields zero.
pub const TEMPLATE: [u8; SIG_STRUCTURE_LEN] = [
    0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x43, 0xa1, 0x01, 0x26,
    0x40, 0x59, 0x01, 0x63, 0xd8, 0x18, 0x59, 0x01, 0x5e, 0xa6, 0x67, 0x76, 0x65, 0x72, 0x73, 0x69,
    0x6f, 0x6e, 0x63, 0x31, 0x2e, 0x30, 0x6f, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74, 0x41, 0x6c, 0x67,
    0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x67, 0x53, 0x48, 0x41, 0x2d, 0x32, 0x35, 0x36, 0x67, 0x64,
    0x6f, 0x63, 0x54, 0x79, 0x70, 0x65, 0x78, 0x1c, 0x65, 0x75, 0x2e, 0x65, 0x75, 0x72, 0x6f, 0x70,
    0x61, 0x2e, 0x65, 0x63, 0x2e, 0x65, 0x75, 0x64, 0x69, 0x2e, 0x6e, 0x79, 0x6d, 0x5f, 0x61, 0x75,
    0x74, 0x68, 0x2e, 0x31, 0x6c, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x44, 0x69, 0x67, 0x65, 0x73, 0x74,
    0x73, 0xa1, 0x6e, 0x65, 0x75, 0x2e, 0x6e, 0x79, 0x6d, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x76,
    0x31, 0xa2, 0x00, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6d, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4b,
    0x65, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0xa1, 0x69, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4b, 0x65,
    0x79, 0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x6c, 0x76, 0x61, 0x6c, 0x69,
    0x64, 0x69, 0x74, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0xa3, 0x66, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64,
    0xc0, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x69, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x46, 0x72, 0x6f, 0x6d,
    0xc0, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6a, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x55, 0x6e, 0x74, 0x69,
    0x6c, 0xc0, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// The private fields: (offset in the Sig_structure, length), in the order the hash circuit takes
/// them: bsc, psc, the device key's x, its sign byte, signed, validFrom, validUntil (157 bytes).
pub const FIELDS: [(usize, usize); 7] =
    [(133, 32), (168, 32), (233, 32), (266, 1), (290, 20), (322, 20), (355, 20)];
pub const FIELDS_LEN: usize = 157;
pub const BSC_AT: usize = 133;
pub const PSC_AT: usize = 168;
pub const DEVICE_X_AT: usize = 233;
pub const DEVICE_SIGN_AT: usize = 266;
pub const SIGNED_AT: usize = 290;
pub const VALID_FROM_AT: usize = 322;
pub const VALID_UNTIL_AT: usize = 355;
/// The validity's offsets in [`Parsed::fields`].
pub const FIELDS_VALID_FROM: usize = 117;
pub const FIELDS_VALID_UNTIL: usize = 137;

/// The Sig_structure's first 128 bytes are the same for every credential of the layout: the
/// hash circuit starts SHA-256 at their state, [`PREFIX_STATE`].
pub const PREFIX_LEN: usize = 128;
pub const PREFIX_STATE: [u32; 8] = [
    0xfebc8c27, 0x7c5c6819, 0x24462151, 0x3093dd16, 0x7da7b2c2, 0xb3a3340b, 0x9fdcd160, 0xbba633fd,
];

const ISSUER_SIGNED_HEAD: &[u8] = b"\xa1\x6aissuerAuth\x84\x43\xa1\x01\x26\xa1\x18\x21";
const PAYLOAD_HEAD: &[u8] = b"\x59\x01\x63\xd8\x18\x59\x01\x5e";
const SIGNATURE_HEAD: &[u8] = b"\x58\x40";

pub struct Parsed {
    /// ["Signature1", h'a10126', h'', payload], as the issuer signed it (375 bytes).
    pub sig_structure: Vec<u8>,
    /// The issuer's signature r || s.
    pub issuer_sig: [u8; 64],
    /// The device key's x, big-endian, and y, big-endian, decompressed from x and the sign byte.
    pub device_x: [u8; 32],
    pub device_y: [u8; 32],
    /// The commitments bsc and psc (valueDigests 0 and 1).
    pub bsc: [u8; 32],
    pub psc: [u8; 32],
}

impl Parsed {
    /// The 157 private bytes, in [`FIELDS`]' order.
    pub fn fields(&self) -> [u8; FIELDS_LEN] {
        let mut out = [0u8; FIELDS_LEN];
        let mut k = 0;
        for (at, n) in FIELDS {
            out[k..k + n].copy_from_slice(&self.sig_structure[at..at + n]);
            k += n;
        }
        out
    }
}

/// Whether `t` reads YYYY-MM-DDThh:mm:ssZ (digits at the digits' places).
pub fn is_tdate(t: &[u8]) -> bool {
    t.len() == 20
        && t.iter().enumerate().all(|(i, &c)| match i {
            4 | 7 => c == b'-',
            10 => c == b'T',
            13 | 16 => c == b':',
            19 => c == b'Z',
            _ => c.is_ascii_digit(),
        })
}

fn in_field(i: usize) -> bool {
    FIELDS.iter().any(|&(at, n)| at <= i && i < at + n)
}

/// The y of the P-256 point with x-coordinate `x` and y's parity `odd` (the COSE_Key sign bit:
/// `f5` when y is odd), or None when no point has that x.
pub fn decompress(x: &[u8; 32], odd: bool) -> Option<[u8; 32]> {
    use p256::elliptic_curve::sec1::{FromEncodedPoint as _, ToEncodedPoint as _};
    let mut sec1 = [0u8; 33];
    sec1[0] = if odd { 0x03 } else { 0x02 };
    sec1[1..].copy_from_slice(x);
    let point = p256::EncodedPoint::from_bytes(sec1).ok()?;
    let affine = Option::<p256::AffinePoint>::from(p256::AffinePoint::from_encoded_point(&point))?;
    let full = affine.to_encoded_point(false);
    full.y().map(|y| (*y).into())
}

/// Parses `issuer_signed` (the IssuerSigned CBOR) against the layout, refusing any deviation
/// ([`Error::Credential`]).
pub fn parse(issuer_signed: &[u8]) -> Result<Parsed, Error> {
    let c = issuer_signed;
    if c.len() < ISSUER_SIGNED_HEAD.len() + 3 || &c[..ISSUER_SIGNED_HEAD.len()] != ISSUER_SIGNED_HEAD {
        return Err(Error::Credential("not the layout's IssuerSigned {issuerAuth} head"));
    }
    // The x5chain bstr, its head minimal.
    let h = ISSUER_SIGNED_HEAD.len();
    let (xlen, xhead) = match c[h] {
        0x58 if c[h + 1] >= 24 => (usize::from(c[h + 1]), 2),
        0x59 => {
            let n = usize::from(c[h + 1]) << 8 | usize::from(c[h + 2]);
            if n < 256 {
                return Err(Error::Credential("x5chain head not minimal"));
            }
            (n, 3)
        }
        _ => return Err(Error::Credential("x5chain is not one certificate bstr of 24 bytes or more")),
    };
    let p = h + xhead + xlen;
    if c.len() != p + PAYLOAD_HEAD.len() + MSO_LEN + SIGNATURE_HEAD.len() + 64 {
        return Err(Error::Credential("credential length is not the layout's"));
    }
    if &c[p..p + PAYLOAD_HEAD.len()] != PAYLOAD_HEAD {
        return Err(Error::Credential("payload is not tag 24 on a 350-byte MSO"));
    }
    let m = p + PAYLOAD_HEAD.len();
    let s = m + MSO_LEN;
    if &c[s..s + 2] != SIGNATURE_HEAD {
        return Err(Error::Credential("signature is not a 64-byte bstr"));
    }
    let mut ss = Vec::with_capacity(SIG_STRUCTURE_LEN);
    ss.extend_from_slice(&TEMPLATE[..25]);
    ss.extend_from_slice(&c[m..s]);
    if (0..SIG_STRUCTURE_LEN).any(|i| !in_field(i) && ss[i] != TEMPLATE[i]) {
        return Err(Error::Credential("the MSO differs from the layout's template"));
    }
    for at in [SIGNED_AT, VALID_FROM_AT, VALID_UNTIL_AT] {
        if !is_tdate(&ss[at..at + 20]) {
            return Err(Error::Credential("a validity date-time is not YYYY-MM-DDThh:mm:ssZ"));
        }
    }
    let odd = match ss[DEVICE_SIGN_AT] {
        0xf5 => true,
        0xf4 => false,
        _ => return Err(Error::Credential("the device key's sign is not a CBOR bool")),
    };
    let a32 = |at: usize| -> [u8; 32] { ss[at..at + 32].try_into().unwrap() };
    let device_x = a32(DEVICE_X_AT);
    let device_y = decompress(&device_x, odd).ok_or(Error::Credential("the device key is not a P-256 point"))?;
    Ok(Parsed {
        issuer_sig: c[s + 2..s + 66].try_into().unwrap(),
        device_x,
        device_y,
        bsc: a32(BSC_AT),
        psc: a32(PSC_AT),
        sig_structure: ss,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_state_is_the_templates() {
        let mut st = crate::sha::IV;
        for b in 0..2 {
            st = crate::sha::compress(&st, &TEMPLATE[64 * b..64 * b + 64]).out;
        }
        assert_eq!(st, PREFIX_STATE);
        assert_eq!(FIELDS.iter().map(|f| f.1).sum::<usize>(), FIELDS_LEN);
        assert!(FIELDS.iter().all(|&(at, _)| at >= PREFIX_LEN));
        assert_eq!(&TEMPLATE[114..129], b"\x6eeu.nym_auth.v1");
    }
}
