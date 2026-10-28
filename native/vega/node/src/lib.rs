//! Node addon: the nym_auth Vega prover and verifier, called in process by Community's server
//! (`server/utils/services.ts`).
//!
//! - [`load_prover`] and [`load_verifier`] build each side's keys from `shapes.zst` once (and,
//!   given the path of rulebook v0.5's `circuits/mdoc-bsc/shapes.zst`, its keys too), on a worker
//!   thread, and resolve to a [`Prover`] or a [`Verifier`] that keeps them. Setup is
//!   deterministic, so keeping the keys keeps nothing about any holder or request.
//! - The prover's native steps: [`Prover::sign`] (the device key signs DeviceAuthentication; the
//!   wallet's PIN screen stands for the phone's unlock and the prover takes no PIN),
//!   [`Prover::witness`] and [`Prover::prove`]. A [`Witness`] lives for the
//!   one server request that makes it: `prove` takes its data out, and nothing else holds it.
//! - [`Verifier::verify`].
//!
//! Inputs and outputs are JSON text shaped as `docs/backend-api.md` describes. Every computation
//! runs as an async task off Node's event loop, and one heavy step runs at a time.
//!
//! With `"profile": true` in a step's JSON (`/tech`'s Profiling switch), the step's metrics also
//! carry `profile`: the sampled stacks (`nym-profile`), and for witness, prove and verify
//! vega-prover's own phases (`nym_vega::phases`).

mod alloc;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use napi::bindgen_prelude::{AsyncTask, Either};
use napi::{Env, Error, Result, Task};
use napi_derive::napi;
use nym_vega::error::Refusal;
use nym_vega::{measure, prover, verifier};

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

fn parse<T: serde::de::DeserializeOwned>(what: &str, input: &str) -> std::result::Result<T, Refusal> {
  serde_json::from_str(input).map_err(|e| Refusal::bad_request(format!("{what}: {e}")))
}

/// The addon's own code, where a sampled stack begins.
const ROOTS: &[&str] = &["nym_vega::", "vega_age::", "vega_prover::"];

/// A boolean field of a step's JSON input (false when absent or not JSON).
fn flag(input: &str, key: &str) -> bool {
  serde_json::from_str::<serde_json::Value>(input).ok().and_then(|v| v.get(key)?.as_bool()).unwrap_or(false)
}

/// Runs a step under the sampler and, when `phases`, vega-prover's phase recorder.
fn profiled<T>(on: bool, phases: bool, heap: bool, f: impl FnOnce() -> T) -> (T, Option<serde_json::Value>) {
  let sampler = nym_profile::Sampler::start(on, ROOTS);
  let (out, recorded) = nym_vega::phases::record(on && phases, heap, f);
  let samples = sampler.finish();
  let profile = (samples.is_some() || recorded.is_some()).then(|| {
    let mut p = samples.unwrap_or_else(|| serde_json::json!({}));
    p["phases"] = recorded.unwrap_or(serde_json::Value::Null);
    p
  });
  (out, profile)
}

/// Puts `profile` into `json.metrics`.
fn attach(json: &mut serde_json::Value, profile: Option<serde_json::Value>) {
  if let Some(p) = profile
    && let Some(m) = json.get_mut("metrics").and_then(|m| m.as_object_mut())
  {
    m.insert("profile".into(), p);
  }
}

fn refusal_json(r: &Refusal) -> String {
  serde_json::json!({ "ok": false, "status": r.status, "error": r.error, "detail": r.detail }).to_string()
}

// ---- loading ----

pub struct LoadProver {
  shapes: PathBuf,
  shapes_v05: Option<PathBuf>,
}

impl Task for LoadProver {
  type Output = prover::Prover;
  type JsValue = Prover;

  fn compute(&mut self) -> Result<Self::Output> {
    guarded(|| prover::Prover::load(&self.shapes, self.shapes_v05.as_deref()))
  }

  fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(Prover { inner: Arc::new(output) })
  }
}

/// Builds the prover key from `shapes` (path to `shapes.zst`), and v0.5's from `shapes_v05`.
#[napi]
pub fn load_prover(shapes: String, shapes_v05: Option<String>) -> AsyncTask<LoadProver> {
  AsyncTask::new(LoadProver { shapes: PathBuf::from(shapes), shapes_v05: shapes_v05.map(PathBuf::from) })
}

pub struct LoadVerifier {
  shapes: PathBuf,
  shapes_v05: Option<PathBuf>,
  trust_anchors_pem: String,
  tolerance_s: i64,
}

impl Task for LoadVerifier {
  type Output = verifier::Verifier;
  type JsValue = Verifier;

  fn compute(&mut self) -> Result<Self::Output> {
    guarded(|| verifier::Verifier::load(&self.shapes, self.shapes_v05.as_deref(), &self.trust_anchors_pem, self.tolerance_s))
  }

  fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(Verifier { inner: Arc::new(output) })
  }
}

/// Builds the verifier key from `shapes`, with the trust anchors (PEM text) and the proof_time
/// tolerance in seconds, and v0.5's from `shapes_v05`.
#[napi]
pub fn load_verifier(shapes: String, trust_anchors_pem: String, tolerance_s: i64, shapes_v05: Option<String>) -> AsyncTask<LoadVerifier> {
  AsyncTask::new(LoadVerifier { shapes: PathBuf::from(shapes), shapes_v05: shapes_v05.map(PathBuf::from), trust_anchors_pem, tolerance_s })
}

// ---- the prover ----

/// The holder side. Keeps the prover key, nothing about any holder.
#[napi]
pub struct Prover {
  inner: Arc<prover::Prover>,
}

/// The witness of one presentation. `prove` takes its data out.
#[napi]
pub struct Witness {
  data: Arc<Mutex<Option<prover::WitnessData>>>,
  summary: String,
  /// The witness step's input asked for a profile, and its thread switch; prove follows both.
  profile: bool,
  parallel: bool,
}

#[napi]
impl Witness {
  /// JSON: proof_time, results, the public inputs the witness claims, counts, witness_ms.
  #[napi(getter)]
  pub fn summary(&self) -> String {
    self.summary.clone()
  }
}

pub struct Sign {
  prover: Arc<prover::Prover>,
  input: String,
}

impl Task for Sign {
  type Output = String;
  type JsValue = String;

  fn compute(&mut self) -> Result<Self::Output> {
    guarded(|| {
      let (out, profile) =
        profiled(flag(&self.input, "profile"), false, false, || parse::<prover::SignInput>("sign", &self.input).and_then(|i| self.prover.sign(&i)));
      Ok(match out {
        Ok(o) => {
          let mut json = serde_json::to_value(o).map_err(|e| e.to_string())?;
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

pub struct MakeWitness {
  prover: Arc<prover::Prover>,
  input: String,
  profile: bool,
  parallel: bool,
}

impl Task for MakeWitness {
  type Output = std::result::Result<prover::WitnessData, Refusal>;
  type JsValue = Either<Witness, String>;

  fn compute(&mut self) -> Result<Self::Output> {
    guarded(|| {
      let guard = measure::exclusive()?;
      let (mut out, profile) = profiled(self.profile, true, !self.parallel, || {
        parse::<prover::WitnessInput>("witness", &self.input).and_then(|i| self.prover.witness(&i))
      });
      drop(guard);
      if let Ok(data) = out.as_mut() {
        attach(&mut data.summary, profile);
      }
      Ok(out)
    })
  }

  fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(match output {
      Ok(data) => {
        let summary = data.summary.to_string();
        Either::A(Witness { data: Arc::new(Mutex::new(Some(data))), summary, profile: self.profile, parallel: self.parallel })
      }
      Err(r) => Either::B(refusal_json(&r)),
    })
  }
}

pub struct Prove {
  prover: Arc<prover::Prover>,
  data: Option<prover::WitnessData>,
  profile: bool,
  parallel: bool,
}

impl Task for Prove {
  type Output = String;
  type JsValue = String;

  fn compute(&mut self) -> Result<Self::Output> {
    let data = self.data.take().ok_or_else(|| reason("the witness was already proved"))?;
    guarded(|| {
      let guard = measure::exclusive()?;
      let (out, profile) = profiled(self.profile, true, !self.parallel, || self.prover.prove(data));
      drop(guard);
      let mut json = out?;
      json["ok"] = serde_json::Value::Bool(true);
      attach(&mut json, profile);
      Ok(json.to_string())
    })
  }

  fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
  }
}

#[napi]
impl Prover {
  /// JSON: implementation, circuits (id, proof system, shapes SHA-256, public-input order),
  /// load_ms, threads.
  #[napi(getter)]
  pub fn info(&self) -> String {
    self.inner.info().to_string()
  }

  /// Step 1, sign. JSON in (`device_key`, `doc_type`, `handover`), JSON out.
  #[napi]
  pub fn sign(&self, input: String) -> AsyncTask<Sign> {
    AsyncTask::new(Sign { prover: self.inner.clone(), input })
  }

  /// Step 2, the witness. JSON in; a Witness, or the refusal as JSON text.
  #[napi]
  pub fn witness(&self, input: String) -> AsyncTask<MakeWitness> {
    let (profile, parallel) = (flag(&input, "profile"), flag(&input, "parallel"));
    AsyncTask::new(MakeWitness { prover: self.inner.clone(), input, profile, parallel })
  }

  /// Step 3, prove: consumes the witness. JSON out (presentation, results, metrics).
  #[napi]
  pub fn prove(&self, witness: &Witness) -> Result<AsyncTask<Prove>> {
    let data = witness.data.lock().map_err(|_| reason("the witness lock is poisoned"))?.take();
    let data = data.ok_or_else(|| reason("the witness was already proved"))?;
    Ok(AsyncTask::new(Prove { prover: self.inner.clone(), data: Some(data), profile: witness.profile, parallel: witness.parallel }))
  }
}

// ---- the verifier ----

/// The verifier side. Keeps the verifier key and the trust anchors.
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
      let (on, parallel) = (flag(&self.input, "profile"), flag(&self.input, "parallel"));
      let (mut out, profile) = profiled(on, true, !parallel, || self.verifier.verify(&input));
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
  /// JSON: implementation, circuits, trust anchors, proof_time tolerance, load_ms, threads.
  #[napi(getter)]
  pub fn info(&self) -> String {
    self.inner.info().to_string()
  }

  /// Verifies a presentation. JSON in (`request`, `credential_query_id`, `presentation`,
  /// `handover`, `now`), JSON out (`ok`, with `results` or the refusal's `code`, `input`, `reason`;
  /// `metrics`).
  #[napi]
  pub fn verify(&self, input: String) -> AsyncTask<Verify> {
    AsyncTask::new(Verify { verifier: self.inner.clone(), input })
  }
}
