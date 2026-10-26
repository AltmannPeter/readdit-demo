//! Session binding: the SessionTranscript of a cross-device OpenID4VP presentation and the
//! challenge digest e2 that the device key signs.
//!
//! Community invokes the wallet with a QR code holding `request_uri` (not the Digital Credentials
//! API), so OpenID4VP 1.0 Appendix B.2.6.1 ("Invocation via Redirects") applies:
//!
//! ```text
//! SessionTranscript     = [null, null, OpenID4VPHandover]
//! OpenID4VPHandover     = ["OpenID4VPHandover", SHA-256(OpenID4VPHandoverInfoBytes)]
//! OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint / null, responseUri]
//! ```
//!
//! `jwkThumbprint` is null for an unencrypted response (`direct_post`). The rulebook ("Binding")
//! puts the transcript in DeviceAuthentication, and SPEC.md §3 makes the message the COSE
//! Sig_structure over DeviceAuthenticationBytes; `vega_age::challenge` builds both.

use serde::Deserialize;
use vega_age::challenge;
use vega_age::fixtures::cbor::{Value, text};
use vega_age::table::sha256;

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

const NULL: [u8; 1] = [0xf6];

/// SessionTranscript of OpenID4VP 1.0 B.2.6.1, encoded.
pub fn session_transcript(
  client_id: &str,
  nonce: &str,
  jwk_thumbprint: Option<&[u8; 32]>,
  response_uri: &str,
) -> Vec<u8> {
  let thumbprint = jwk_thumbprint.map_or(Value::Encoded(NULL.to_vec()), |t| Value::Bytes(t.to_vec()));
  let info = Value::Array(vec![text(client_id), text(nonce), thumbprint, text(response_uri)]).encode();
  let handover = Value::Array(vec![text("OpenID4VPHandover"), Value::Bytes(sha256(&info).to_vec())]);
  Value::Array(vec![Value::Encoded(NULL.to_vec()), Value::Encoded(NULL.to_vec()), handover]).encode()
}

/// The message the device key signs (ES256): the COSE Sig_structure over DeviceAuthenticationBytes.
pub fn device_message(session_transcript: &[u8], doc_type: &str) -> Vec<u8> {
  challenge::device_authentication(session_transcript, doc_type)
}

/// The challenge digest e2 = SHA-256(message), a public input of the circuit.
pub fn challenge_digest(session_transcript: &[u8], doc_type: &str) -> [u8; 32] {
  challenge::mdoc(session_transcript, doc_type)
}

#[cfg(test)]
mod tests {
  use super::*;

  /// OpenID4VP 1.0, Appendix B.2.6.1: the non-normative example of OpenID4VPHandoverInfo,
  /// OpenID4VPHandover and SessionTranscript. An independent known answer for the encoding.
  #[test]
  fn openid4vp_appendix_b261_example() {
    let thumbprint: [u8; 32] =
      crate::unhex("thumbprint", "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047")
        .expect("hex");
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
}
