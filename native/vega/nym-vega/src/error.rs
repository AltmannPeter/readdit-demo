//! The refusals of the prover's steps, with the HTTP-style status and code of
//! `docs/backend-api.md`.

use serde::Serialize;

/// A refusal the holder side reports to the wallet. `error` is the contract's code; `detail`
/// says what was wrong.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Refusal {
  pub status: u16,
  pub error: &'static str,
  pub detail: String,
}

impl Refusal {
  fn new(status: u16, error: &'static str, detail: impl Into<String>) -> Self {
    Refusal { status, error, detail: detail.into() }
  }

  /// A predicate does not hold for the holder's data (rulebook: the wallet then sends
  /// `access_denied`).
  pub fn unsatisfiable(detail: impl Into<String>) -> Self {
    Self::new(422, "unsatisfiable", detail)
  }

  pub fn unsupported_circuit(detail: impl Into<String>) -> Self {
    Self::new(400, "unsupported_circuit", detail)
  }

  pub fn unsupported_request(detail: impl Into<String>) -> Self {
    Self::new(400, "unsupported_request", detail)
  }

  pub fn unsupported_config(detail: impl Into<String>) -> Self {
    Self::new(400, "unsupported_config", detail)
  }

  pub fn unsupported_function(detail: impl Into<String>) -> Self {
    Self::new(400, "unsupported_function", detail)
  }

  /// The credential material the wallet sent is malformed or inconsistent.
  pub fn bad_credential(detail: impl Into<String>) -> Self {
    Self::new(400, "bad_credential", detail)
  }

  /// The call itself is malformed.
  pub fn bad_request(detail: impl Into<String>) -> Self {
    Self::new(400, "bad_request", detail)
  }
}
