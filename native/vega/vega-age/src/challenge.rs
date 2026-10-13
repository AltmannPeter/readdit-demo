//! The challenge the device key signs, as the nym_auth statement requires it.
//!
//! The rules verify the device key's ECDSA signature on a 256-bit digest that the verifier names
//! ([`crate::presentation::Public::challenge`]), and they hash nothing for it. The verifier
//! computes the digest from values it knows. The wallet signs the message whose SHA-256 digest it
//! is, with ES256.
//!
//! - **SD-JWT VC.** The device signs the verifier's request, domain-separated and length-prefixed,
//!   TupleHash-style: the message is `nym_auth/v1/device-challenge` ‖ len(nonce) ‖
//!   nonce ‖ len(client_id) ‖ client_id ‖ len(origin) ‖ origin, each len the part's byte count as
//!   4 big-endian bytes ([`sd_jwt_message`]). The domain keeps the wallet from serving as a
//!   signing oracle for another protocol that shares the device key, and the lengths keep two
//!   requests whose parts run together into the same bytes apart. There is no KB-JWT and no
//!   `sd_hash`: the device key is read from the same signed payload as the birth date, and the
//!   fresh challenge binds the proof to this presentation.
//! - **mdoc.** The device signs DeviceAuthentication, as ISO/IEC 18013-5 (clause 9.1.3) and the
//!   PID Rulebook require: the COSE_Sign1 Sig_structure (RFC 9052, clause 4.4) whose detached
//!   payload is DeviceAuthenticationBytes, which holds the SessionTranscript, the docType and
//!   empty DeviceNameSpaces ([`device_authentication`]).
//!
//! [`dc_api_session_transcript`] builds the SessionTranscript of an OpenID4VP presentation over
//! the Digital Credentials API (OpenID4VP 1.0, appendix B.2.6.2).

use crate::table::sha256;

/// The domain of the SD-JWT challenge.
pub const SD_JWT_DOMAIN: &[u8] = b"nym_auth/v1/device-challenge";

/// The protected header of the device's COSE_Sign1: the map {1: −7}, the algorithm ES256.
pub const ES256_HEADER: [u8; 3] = [0xa1, 0x01, 0x26];

/// The head of a CBOR data item of major type `major` whose argument is `n` (RFC 8949, clause 3).
fn head(major: u8, n: usize) -> Vec<u8> {
  let m = major << 5;
  let n = n as u64;
  match n {
    0..24 => vec![m | n as u8],
    24..0x100 => vec![m | 24, n as u8],
    0x100..0x1_0000 => [&[m | 25][..], &(n as u16).to_be_bytes()].concat(),
    0x1_0000..0x1_0000_0000 => [&[m | 26][..], &(n as u32).to_be_bytes()].concat(),
    _ => [&[m | 27][..], &n.to_be_bytes()].concat(),
  }
}

/// A CBOR byte string.
fn bytes(content: &[u8]) -> Vec<u8> {
  [head(2, content.len()), content.to_vec()].concat()
}

/// A CBOR text string.
fn text(content: &str) -> Vec<u8> {
  [head(3, content.len()), content.as_bytes().to_vec()].concat()
}

/// Tag 24 on a byte string holding an encoded data item: `bstr .cbor`.
fn embedded(encoded: &[u8]) -> Vec<u8> {
  [head(6, 24), bytes(encoded)].concat()
}

/// The length prefix of a part of `len` bytes: its byte count as 4 big-endian bytes. A part of
/// 2^32 bytes or more has none.
pub fn length_prefix(len: usize) -> Result<[u8; 4], String> {
  u32::try_from(len)
    .map(u32::to_be_bytes)
    .map_err(|_| format!("a request part of {len} bytes is longer than 4 bytes can count"))
}

/// A part of the SD-JWT message: its length prefix, then its bytes.
fn prefixed(part: &str) -> Result<Vec<u8>, String> {
  Ok([&length_prefix(part.len())?[..], part.as_bytes()].concat())
}

/// The message the device signs for an SD-JWT VC: the domain, then the request's nonce, the
/// verifier's client_id and the origin, each after its length.
pub fn sd_jwt_message(nonce: &str, client_id: &str, origin: &str) -> Result<Vec<u8>, String> {
  Ok([SD_JWT_DOMAIN.to_vec(), prefixed(nonce)?, prefixed(client_id)?, prefixed(origin)?].concat())
}

/// The SD-JWT challenge: the digest of [`sd_jwt_message`].
pub fn sd_jwt(nonce: &str, client_id: &str, origin: &str) -> Result<[u8; 32], String> {
  sd_jwt_message(nonce, client_id, origin).map(|message| sha256(&message))
}

/// The Sig_structure the device signs for an mdoc: `["Signature1", protected, h'', payload]`,
/// where the payload is DeviceAuthenticationBytes, tag 24 on the encoded
/// `["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]`, and
/// DeviceNameSpacesBytes is tag 24 on the empty map. `session_transcript` is encoded CBOR.
pub fn device_authentication(session_transcript: &[u8], doc_type: &str) -> Vec<u8> {
  let name_spaces = embedded(&[0xa0]);
  let authentication = [
    head(4, 4),
    text("DeviceAuthentication"),
    session_transcript.to_vec(),
    text(doc_type),
    name_spaces,
  ]
  .concat();
  let payload = embedded(&authentication);
  [head(4, 4), text("Signature1"), bytes(&ES256_HEADER), bytes(&[]), bytes(&payload)].concat()
}

/// The mdoc challenge: the digest of [`device_authentication`].
pub fn mdoc(session_transcript: &[u8], doc_type: &str) -> [u8; 32] {
  sha256(&device_authentication(session_transcript, doc_type))
}

/// The SessionTranscript `[null, null, OpenID4VPDCAPIHandover]` of a presentation over the Digital
/// Credentials API. The handover is `["OpenID4VPDCAPIHandover", h]`, where h is the SHA-256 of the
/// encoded `[origin, nonce, jwkThumbprint]`. The thumbprint is the one of the key that encrypts
/// the response, or null for an unencrypted response.
pub fn dc_api_session_transcript(
  origin: &str,
  nonce: &str,
  jwk_thumbprint: Option<&[u8; 32]>,
) -> Vec<u8> {
  let thumbprint = jwk_thumbprint.map_or(vec![0xf6], |t| bytes(t));
  let info = [head(4, 3), text(origin), text(nonce), thumbprint].concat();
  let handover = [head(4, 2), text("OpenID4VPDCAPIHandover"), bytes(&sha256(&info))].concat();
  [head(4, 3), vec![0xf6, 0xf6], handover].concat()
}
