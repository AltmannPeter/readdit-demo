//! The holder's credential: an ISO/IEC 18013-5 IssuerSigned structure of the nym_auth attestation
//! (docType and namespace `eu.europa.ec.eudi.nym_auth.1`) in the **decoy-digest layout**.
//!
//! In this layout the MSO's `valueDigests` hold the commitments themselves: digestID 0 is
//! `bsc = SHA-256(secret_seed || birth_date)` and digestID 1 is `psc` (SHA-256(private_seed), or
//! 32 zero bytes). There are no IssuerSignedItems and no `nameSpaces`. The MSO is exactly 398
//! bytes in a fixed key order, so the COSE Sig_structure is exactly 423 bytes (7 SHA-256 blocks
//! once padded) and every field sits at a fixed offset ([`TEMPLATE`], [`FIELDS`]).
//!
//! The credential must be exactly:
//!
//! ```text
//! a1 6a "issuerAuth"                       IssuerSigned: { "issuerAuth": COSE_Sign1 }
//!   84                                     COSE_Sign1 [
//!     43 a1 01 26                            protected: { 1: -7 } (ES256)
//!     a1 18 21 <bstr x5chain>                unprotected: { 33: x5chain } (one certificate)
//!     59 01 93 d8 18 59 01 8e <MSO, 398>     payload: tag 24 on the 398-byte MSO
//!     58 40 <r || s>                         signature ]
//! ```
//!
//! and the Sig_structure built from it must equal [`TEMPLATE`] at every byte outside the seven
//! private fields, whose three tdates must read `YYYY-MM-DDThh:mm:ssZ`. Anything else is refused
//! before proving ([`parse`]); the hash circuit checks the same bytes again (they are its
//! constants).

use crate::Error;

pub const DOC_TYPE: &str = "eu.europa.ec.eudi.nym_auth.1";
pub const NAMESPACE: &str = "eu.europa.ec.eudi.nym_auth.1";

/// The Sig_structure's length, and its SHA-256 blocks once padded.
pub const SIG_STRUCTURE_LEN: usize = 423;
pub const SIGNED_BLOCKS: usize = 7;
/// The MSO's length.
pub const MSO_LEN: usize = 398;

/// The Sig_structure template: every constant byte of the layout, the private fields zero.
pub const TEMPLATE: [u8; SIG_STRUCTURE_LEN] = [
    0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x43, 0xa1, 0x01, 0x26,
    0x40, 0x59, 0x01, 0x93, 0xd8, 0x18, 0x59, 0x01, 0x8e, 0xa6, 0x67, 0x76, 0x65, 0x72, 0x73, 0x69,
    0x6f, 0x6e, 0x63, 0x31, 0x2e, 0x30, 0x6f, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74, 0x41, 0x6c, 0x67,
    0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x67, 0x53, 0x48, 0x41, 0x2d, 0x32, 0x35, 0x36, 0x67, 0x64,
    0x6f, 0x63, 0x54, 0x79, 0x70, 0x65, 0x78, 0x1c, 0x65, 0x75, 0x2e, 0x65, 0x75, 0x72, 0x6f, 0x70,
    0x61, 0x2e, 0x65, 0x63, 0x2e, 0x65, 0x75, 0x64, 0x69, 0x2e, 0x6e, 0x79, 0x6d, 0x5f, 0x61, 0x75,
    0x74, 0x68, 0x2e, 0x31, 0x6c, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x44, 0x69, 0x67, 0x65, 0x73, 0x74,
    0x73, 0xa1, 0x78, 0x1c, 0x65, 0x75, 0x2e, 0x65, 0x75, 0x72, 0x6f, 0x70, 0x61, 0x2e, 0x65, 0x63,
    0x2e, 0x65, 0x75, 0x64, 0x69, 0x2e, 0x6e, 0x79, 0x6d, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x31,
    0xa2, 0x00, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6d, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4b, 0x65,
    0x79, 0x49, 0x6e, 0x66, 0x6f, 0xa1, 0x69, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4b, 0x65, 0x79,
    0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, 0x76, 0x61, 0x6c, 0x69,
    0x64, 0x69, 0x74, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0xa3, 0x66, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64,
    0xc0, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x69, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x46, 0x72, 0x6f, 0x6d,
    0xc0, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6a, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x55, 0x6e, 0x74, 0x69,
    0x6c, 0xc0, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// The private fields: (offset in the Sig_structure, length), in the order the hash circuit takes
/// them: bsc, psc, the device key's x and y, signed, validFrom, validUntil (188 bytes in all).
pub const FIELDS: [(usize, usize); 7] =
    [(148, 32), (183, 32), (248, 32), (283, 32), (338, 20), (370, 20), (403, 20)];
pub const FIELDS_LEN: usize = 188;
pub const BSC_AT: usize = 148;
pub const PSC_AT: usize = 183;
pub const DEVICE_X_AT: usize = 248;
pub const DEVICE_Y_AT: usize = 283;
pub const SIGNED_AT: usize = 338;
pub const VALID_FROM_AT: usize = 370;
pub const VALID_UNTIL_AT: usize = 403;

/// The Sig_structure's first 128 bytes are the same for every credential of the layout: the
/// hash circuit starts SHA-256 at their state, [`PREFIX_STATE`].
pub const PREFIX_LEN: usize = 128;
pub const PREFIX_STATE: [u32; 8] = [
    0x3f5dcfbc, 0xcbd48de1, 0x3d035a41, 0x970caaf1, 0x81b81cb5, 0xd02831c8, 0x02994fba, 0x56c9b760,
];

const ISSUER_SIGNED_HEAD: &[u8] = b"\xa1\x6aissuerAuth\x84\x43\xa1\x01\x26\xa1\x18\x21";
const PAYLOAD_HEAD: &[u8] = b"\x59\x01\x93\xd8\x18\x59\x01\x8e";
const SIGNATURE_HEAD: &[u8] = b"\x58\x40";

pub struct Parsed {
    /// ["Signature1", h'a10126', h'', payload], as the issuer signed it (423 bytes).
    pub sig_structure: Vec<u8>,
    /// The issuer's signature r || s.
    pub issuer_sig: [u8; 64],
    /// The device key's coordinates, big-endian.
    pub device_x: [u8; 32],
    pub device_y: [u8; 32],
    /// The commitments bsc and psc (valueDigests 0 and 1).
    pub bsc: [u8; 32],
    pub psc: [u8; 32],
}

impl Parsed {
    /// The 188 private bytes, in [`FIELDS`]' order.
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
        return Err(Error::Credential("payload is not tag 24 on a 398-byte MSO"));
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
    let a32 = |at: usize| -> [u8; 32] { ss[at..at + 32].try_into().unwrap() };
    Ok(Parsed {
        issuer_sig: c[s + 2..s + 66].try_into().unwrap(),
        device_x: a32(DEVICE_X_AT),
        device_y: a32(DEVICE_Y_AT),
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
    }
}
