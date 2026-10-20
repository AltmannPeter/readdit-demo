//! The BBS credential as the wallet stores it (`app/wallet/demo-wallet-bbs.json`):
//!
//! ```json
//! { "format": "bbs_cd", "schema_id": "...", "issuer_params": "<base64url>",
//!   "signature": "<base64url>", "messages": ["<64 hex digits>", ...] }
//! ```
//!
//! `issuer_params` is `IssuerParams::encode` (the issuer's public key and the schema), `signature`
//! the ETSI signature, and `messages` the signed messages in schema order: a SCALAR message as its
//! 32 bytes big-endian in hex, an OCTETS message as `"o:"` and base64url.

use bbs_cd::types::{Message, ScalarInput};
use bbs_cd_plugin::issuer::{Credential, IssuerParams};
use serde::{Deserialize, Serialize};

use crate::profile::{self, SCHEMA_ID};
use crate::{b64url, unb64url};

/// The attestation's encoding (the `source_format` of a `zkp_req` query).
pub const FORMAT: &str = "bbs_cd";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialJson {
  pub format: String,
  pub schema_id: String,
  pub issuer_params: String,
  pub signature: String,
  pub messages: Vec<String>,
}

impl CredentialJson {
  pub fn from_credential(c: &Credential) -> Self {
    CredentialJson {
      format: FORMAT.into(),
      schema_id: c.issuer.schema.id().into(),
      issuer_params: b64url(&c.issuer.encode()),
      signature: b64url(&c.signature),
      messages: c
        .messages
        .iter()
        .map(|m| match m {
          Message::Scalar(s) => hex::encode(s.0),
          Message::Octets(o) => format!("o:{}", b64url(o)),
        })
        .collect(),
    }
  }

  /// Decodes and checks the credential: the format, our schema, the layout, and the issuer's
  /// signature (`Credential::verify`).
  pub fn decode(&self) -> Result<Credential, String> {
    if self.format != FORMAT {
      return Err(format!("format {}, expected {FORMAT}", self.format));
    }
    let issuer = IssuerParams::decode(&unb64url("issuer_params", &self.issuer_params)?).map_err(|e| format!("issuer_params: {e}"))?;
    if issuer.schema.id() != SCHEMA_ID || self.schema_id != SCHEMA_ID {
      return Err(format!("schema {}, expected {SCHEMA_ID}", issuer.schema.id()));
    }
    if issuer.schema.digest() != profile::schema().map_err(|e| e.to_string())?.digest() {
      return Err("the schema is not the profile's".into());
    }
    let messages = self
      .messages
      .iter()
      .enumerate()
      .map(|(i, m)| match m.strip_prefix("o:") {
        Some(o) => Ok(Message::Octets(unb64url("message", o)?)),
        None => {
          let b: [u8; 32] = hex::decode(m)
            .map_err(|e| format!("message {i}: {e}"))?
            .try_into()
            .map_err(|_| format!("message {i} is not 32 bytes"))?;
          Ok(Message::Scalar(ScalarInput(b)))
        }
      })
      .collect::<Result<Vec<_>, String>>()?;
    let c = Credential { issuer, signature: unb64url("signature", &self.signature)?, messages };
    c.verify().map_err(|e| e.to_string())?;
    Ok(c)
  }
}
