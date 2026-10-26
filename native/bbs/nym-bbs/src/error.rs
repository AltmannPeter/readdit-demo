//! The prover's refusals, with the HTTP-style status and code of `docs/backend-api.md`
//! (the same codes as the Vega prover's).

use serde::Serialize;

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

  /// A predicate does not hold for the holder's data (the wallet then sends `access_denied`).
  pub fn unsatisfiable(detail: impl Into<String>) -> Self {
    Self::new(422, "unsatisfiable", detail)
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

  /// The request does not offer this scheme (`unsupported_circuit` in the contract's words).
  pub fn unsupported_scheme(detail: impl Into<String>) -> Self {
    Self::new(400, "unsupported_circuit", detail)
  }

  pub fn bad_credential(detail: impl Into<String>) -> Self {
    Self::new(400, "bad_credential", detail)
  }

  pub fn bad_request(detail: impl Into<String>) -> Self {
    Self::new(400, "bad_request", detail)
  }
}
