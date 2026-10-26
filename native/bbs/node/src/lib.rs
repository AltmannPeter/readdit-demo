//! Node addon: the BBS (`bbs_cd`, committed disclosures) prover and verifier, called in process by
//! Community's server (`server/utils/services.ts`).
//!
//! - [`load_prover`] builds the date-range tables and resolves to a [`Prover`];
//!   [`load_verifier`] reads the trusted issuer parameters and resolves to a [`Verifier`].
//! - [`Prover::prove`]: one presentation (the device key signs inside, `ecdsa-pop` hashed mode).
//! - [`Verifier::verify`].
//!
//! Inputs and outputs are JSON text shaped as `docs/backend-api.md` describes. Every computation
//! runs as an async task off Node's event loop, and one heavy step runs at a time.
//!
//! With `"profile": true` in a step's JSON (`/tech`'s Profiling switch), the step's metrics also
//! carry `profile`: the sampled stacks (`nym-profile`).

mod alloc;

use std::sync::Arc;

use napi::bindgen_prelude::AsyncTask;
use napi::{Env, Error, Result, Task};
use napi_derive::napi;
use nym_bbs::error::Refusal;
use nym_bbs::{measure, prover, verifier};

fn reason(e: impl std::fmt::Display) -> Error {
  Error::from_reason(e.to_string())
}

/// Runs `f`, turning a panic into an error, so a bug rejects the promise instead of ending Node.
fn guarded<T>(f: impl FnOnce() -> std::result::Result<T, String>) -> Result<T> {
  match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
    Ok(Ok(v)) => Ok(v),
    Ok(Err(e)) => Err(reason(e)),
    Err(p) => {
      let what = p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned());
      Err(reason(format!("panic: {}", what.unwrap_or_else(|| "unknown".into()))))
    }
  }
}

/// The addon's own code and bbs-cd-plugins, where a sampled stack begins.
const ROOTS: &[&str] = &["nym_bbs::", "bbs_cd::", "bbs_cd_plugin::", "cd_"];

/// A boolean field of a step's JSON input (false when absent or not JSON).
fn flag(input: &str, key: &str) -> bool {
  serde_json::from_str::<serde_json::Value>(input).ok().and_then(|v| v.get(key)?.as_bool()).unwrap_or(false)
}

/// Runs a step under the sampler.
fn profiled<T>(on: bool, f: impl FnOnce() -> T) -> (T, Option<serde_json::Value>) {
  let sampler = nym_profile::Sampler::start(on, ROOTS);
  let out = f();
  (out, sampler.finish())
}

/// Puts `profile` into `json.metrics`.
fn attach(json: &mut serde_json::Value, profile: Option<serde_json::Value>) {
  if let (Some(p), Some(m)) = (profile, json.get_mut("metrics").and_then(|m| m.as_object_mut())) {
    m.insert("profile".into(), p);
  }
}

fn refusal_json(r: &Refusal) -> String {
  serde_json::json!({ "ok": false, "status": r.status, "error": r.error, "detail": r.detail }).to_string()
}

// ---- loading ----

pub struct LoadProver;

impl Task for LoadProver {
  type Output = prover::Prover;
  type JsValue = Prover;

  fn compute(&mut self) -> Result<Self::Output> {
    guarded(|| Ok(prover::Prover::load()))
  }

  fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(Prover { inner: Arc::new(output) })
  }
}

#[napi]
pub fn load_prover() -> AsyncTask<LoadProver> {
  AsyncTask::new(LoadProver)
}

pub struct LoadVerifier {
  issuer_params: Vec<u8>,
}

impl Task for LoadVerifier {
  type Output = verifier::Verifier;
  type JsValue = Verifier;

  fn compute(&mut self) -> Result<Self::Output> {
    guarded(|| verifier::Verifier::load(&self.issuer_params))
  }

  fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(Verifier { inner: Arc::new(output) })
  }
}

/// `issuer_params_path`: the trusted issuer's parameters (`demo/issuer-params.bin`).
#[napi]
pub fn load_verifier(issuer_params_path: String) -> Result<AsyncTask<LoadVerifier>> {
  let issuer_params = std::fs::read(&issuer_params_path).map_err(|e| reason(format!("{issuer_params_path}: {e}")))?;
  Ok(AsyncTask::new(LoadVerifier { issuer_params }))
}

// ---- the prover ----

#[napi]
pub struct Prover {
  inner: Arc<prover::Prover>,
}

pub struct Prove {
  prover: Arc<prover::Prover>,
  input: String,
}

impl Task for Prove {
  type Output = String;
  type JsValue = String;

  fn compute(&mut self) -> Result<Self::Output> {
    guarded(|| {
      let input: std::result::Result<prover::ProveInput, Refusal> =
        serde_json::from_str(&self.input).map_err(|e| Refusal::bad_request(format!("prove: {e}")));
      let guard = measure::exclusive()?;
      let (out, profile) = profiled(flag(&self.input, "profile"), || input.and_then(|i| self.prover.prove(&i)));
      drop(guard);
      Ok(match out {
        Ok(mut json) => {
          json["ok"] = serde_json::Value::Bool(true);
          attach(&mut json, profile);
          json.to_string()
        }
        Err(r) => refusal_json(&r),
      })
    })
  }

  fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
  }
}

#[napi]
impl Prover {
  /// JSON: implementation, schemes, load_ms, threads.
  #[napi(getter)]
  pub fn info(&self) -> String {
    self.inner.info().to_string()
  }

  /// One presentation. JSON in (`request`, `credential_query_id`, `handover`, `credential`,
  /// `device_key`), JSON out (`ok`, with `presentation`, `results`, `metrics`, or the refusal).
  #[napi]
  pub fn prove(&self, input: String) -> AsyncTask<Prove> {
    AsyncTask::new(Prove { prover: self.inner.clone(), input })
  }
}

// ---- the verifier ----

#[napi]
pub struct Verifier {
  inner: Arc<verifier::Verifier>,
}

pub struct Verify {
  verifier: Arc<verifier::Verifier>,
  input: String,
}

impl Task for Verify {
  type Output = String;
  type JsValue = String;

  fn compute(&mut self) -> Result<Self::Output> {
    guarded(|| {
      let input: verifier::VerifyInput = serde_json::from_str(&self.input).map_err(|e| format!("verify: {e}"))?;
      let guard = measure::exclusive()?;
      let (mut out, profile) = profiled(flag(&self.input, "profile"), || self.verifier.verify(&input));
      drop(guard);
      attach(&mut out, profile);
      Ok(out.to_string())
    })
  }

  fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
  }
}

#[napi]
impl Verifier {
  /// JSON: implementation, schemes, the trusted issuer, load_ms.
  #[napi(getter)]
  pub fn info(&self) -> String {
    self.inner.info().to_string()
  }

  /// JSON in (`request`, `credential_query_id`, `presentation`, `handover`), JSON out (`ok`, with
  /// `results` or the refusal's `code` and `reason`; `metrics`).
  #[napi]
  pub fn verify(&self, input: String) -> AsyncTask<Verify> {
    AsyncTask::new(Verify { verifier: self.inner.clone(), input })
  }
}
