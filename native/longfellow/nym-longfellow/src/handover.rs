//! Session binding: the SessionTranscript of a cross-device OpenID4VP presentation and the
//! challenge digest e2 that the device key signs. The same as `native/vega` (nym-vega
//! `handover`).
//!
//! Readdit invokes the wallet with a QR code holding `request_uri` (not the Digital Credentials
//! API), so OpenID4VP 1.0 Appendix B.2.6.1 ("Invocation via Redirects") applies:
//!
//! ```text
//! SessionTranscript     = [null, null, OpenID4VPHandover]
//! OpenID4VPHandover     = ["OpenID4VPHandover", SHA-256(OpenID4VPHandoverInfoBytes)]
//! OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint / null, responseUri]
//! ```
//!
//! The device signs the COSE Sig_structure over DeviceAuthenticationBytes (SPEC.md §3), and
//! e2 = SHA-256 of that message. The SessionTranscript bytes also seed the proof's Fiat–Shamir
//! transcript (SPEC.md L6.1).

use serde::Deserialize;

use crate::cbor::{NULL, bstr, embedded, tstr, write_head};
use crate::sha256;

/// The values of the handover, as the verifier's session store holds them.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Handover {
  pub client_id: String,
  pub nonce: String,
  pub response_uri: String,
  /// base64url of the RFC 7638 thumbprint of the response encryption key; null without
  /// encryption.
  pub jwk_thumbprint: Option<String>,
}

impl Handover {
  /// The thumbprint's 32 bytes, if the response is encrypted.
  pub fn thumbprint(&self) -> Result<Option<[u8; 32]>, String> {
    match &self.jwk_thumbprint {
      None => Ok(None),
      Some(t) => {
        let bytes = crate::unb64url("handover.jwk_thumbprint", t)?;
        let bytes: [u8; 32] =
          bytes.try_into().map_err(|_| "handover.jwk_thumbprint is not 32 bytes".to_string())?;
        Ok(Some(bytes))
      }
    }
  }

  /// SessionTranscript `[null, null, OpenID4VPHandover]`, encoded.
  pub fn session_transcript(&self) -> Result<Vec<u8>, String> {
    Ok(session_transcript(&self.client_id, &self.nonce, self.thumbprint()?.as_ref(), &self.response_uri))
  }
}

/// SessionTranscript of OpenID4VP 1.0 B.2.6.1, encoded.
pub fn session_transcript(
  client_id: &str,
  nonce: &str,
  jwk_thumbprint: Option<&[u8; 32]>,
  response_uri: &str,
) -> Vec<u8> {
  let thumbprint = jwk_thumbprint.map_or(vec![NULL], |t| bstr(t));
  let info = [write_head(4, 4), tstr(client_id), tstr(nonce), thumbprint, tstr(response_uri)].concat();
  let handover = [write_head(4, 2), tstr("OpenID4VPHandover"), bstr(&sha256(&info))].concat();
  [write_head(4, 3), vec![NULL, NULL], handover].concat()
}

/// The protected header of the device's COSE_Sign1: {1: −7}, ES256.
const ES256_HEADER: [u8; 3] = [0xa1, 0x01, 0x26];

/// The message the device key signs (ES256): `["Signature1", h'A10126', h'', DeviceAuthenticationBytes]`,
/// DeviceAuthenticationBytes = #6.24(bstr(["DeviceAuthentication", SessionTranscript, docType, #6.24(bstr(h'A0'))])).
pub fn device_message(session_transcript: &[u8], doc_type: &str) -> Vec<u8> {
  let authentication =
    [write_head(4, 4), tstr("DeviceAuthentication"), session_transcript.to_vec(), tstr(doc_type), embedded(&[0xa0])]
      .concat();
  [write_head(4, 4), tstr("Signature1"), bstr(&ES256_HEADER), bstr(&[]), bstr(&embedded(&authentication))].concat()
}

/// The challenge digest e2 = SHA-256(message), a public input of the signature circuit.
pub fn challenge_digest(session_transcript: &[u8], doc_type: &str) -> [u8; 32] {
  sha256(&device_message(session_transcript, doc_type))
}

#[cfg(test)]
mod tests {
  use super::*;

  /// OpenID4VP 1.0, Appendix B.2.6.1: the non-normative example of the SessionTranscript.
  #[test]
  fn openid4vp_appendix_b261_example() {
    let thumbprint: [u8; 32] =
      crate::unhex("thumbprint", "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047").expect("hex");
    let transcript = session_transcript(
      "x509_san_dns:example.com",
      "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
      Some(&thumbprint),
      "https://example.com/response",
    );
    assert_eq!(
      crate::hex(&transcript),
      "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"
    );
  }

  /// The archive's fixture (verifier 1): the same DeviceAuthentication over its DC API
  /// transcript gives its challenge digest.
  #[test]
  fn device_message_matches_the_archive() {
    let info = [write_head(4, 3), tstr("https://verifier.example"), tstr("pOA0oqEAhLnqug2r7Ve4tQ"), vec![NULL]].concat();
    let st = [write_head(4, 3), vec![NULL, NULL], write_head(4, 2), tstr("OpenID4VPDCAPIHandover"), bstr(&sha256(&info))]
      .concat();
    assert_eq!(
      crate::hex(&challenge_digest(&st, crate::circuit::DOC_TYPE)),
      "7eea0f8e073961c3e82e9562e0f79edaa66dbfc17eaf0ac0596a987733516dd9"
    );
  }
}
