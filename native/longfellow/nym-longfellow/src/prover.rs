//! The holder's native steps, as a phone would run them, with the same interface as the Vega
//! prover (`native/vega`, nym-vega `prover`). The wallet brings the credential material to each
//! step; the prover keeps only the circuits.
//!
//! 1. [`Prover::sign`]: the device key signs DeviceAuthentication (ES256). The wallet's PIN screen
//!    stands for the phone's unlock; any PIN unlocks in this demo, so the prover takes none.
//! 2. [`Prover::witness`]: the credential taken apart, every holder-side check, and both input
//!    vectors (SPEC.md L3 to L5).
//! 3. [`Prover::prove`]: the two-circuit proof (SPEC.md L6.2), and the presentation.
//!
//! Under rulebook v0.5 the circuits are `nym-auth-zk`'s (`bsc`, [`crate::v05`]): the witness step
//! makes the holder-side checks of the package's INTEGRATION.md §6 and keeps the request and the
//! holder material, and the prove step lets the crate build the witness and both proofs.

use std::path::Path;
use std::time::Instant;

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature as EcdsaSignature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json, json};

use crate::circuit::{CIRCUIT_ID, DOC_TYPE, PROOF_SYSTEM, PUBLIC_INPUTS, RUNTIME};
use crate::error::Refusal;
use crate::handover::{self, Handover};
use crate::measure::{Heap, Peak, mb, ms};
use crate::presentation::{Presentation, ResultValue};
use crate::request::{RequestObject, Rulebook, Statement, statement_for};
use crate::witness::{self, Private, Public};
use crate::x509::PublicKey;
use crate::zk::{Circuits, ZkProverPair};
use crate::{bsc, dates, hex, mdoc, unb64url, unhex, v05, x509};
use nym_auth_zk as v5;

/// The device key as the wallet holds it: a P-256 JWK with its private part.
#[derive(Clone, Debug, Deserialize)]
pub struct DeviceKey {
  pub kty: String,
  pub crv: String,
  pub x: String,
  pub y: String,
  pub d: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SignInput {
  pub device_key: DeviceKey,
  pub doc_type: String,
  pub handover: Handover,
}

#[derive(Clone, Debug, Serialize)]
pub struct SignOutput {
  /// r ‖ s, hex.
  pub device_signature: String,
  pub session_transcript: String,
  pub challenge_digest: String,
  pub metrics: Json,
}

/// The credential as the wallet holds it.
#[derive(Clone, Debug, Deserialize)]
pub struct Credential {
  pub format: String,
  pub doctype: String,
  /// base64url IssuerSigned.
  pub issuer_signed: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct WitnessInput {
  pub system_id: String,
  pub credential_query_id: String,
  pub request: RequestObject,
  pub handover: Handover,
  pub credential: Credential,
  /// 16 bytes, hex.
  pub secret_seed: String,
  /// r ‖ s, hex, from [`Prover::sign`].
  pub device_signature: String,
  /// The rulebook version the wallet read the request under: "0.4" (absent) or "0.5".
  #[serde(default)]
  pub rulebook: Option<String>,
  /// v0.5: the holder's birth date, `YYYY-MM-DD` (10 bytes), which opens `bsc` with secret_seed.
  #[serde(default)]
  pub birth_date: Option<String>,
}

/// What the prove step proves from: v0.4's two input vectors, or v0.5's first phase
/// (`nym_auth_zk::Prebuilt`: the checks, the statement, the MAC keys, the hash circuit's witness and
/// its commitment) and the device signature for the second.
enum Body {
  V04 { witness: witness::Witness, transcript_seed: Vec<u8> },
  V05 { prebuilt: v5::Prebuilt, device_signature: [u8; 64] },
}

/// The witness of one presentation, which [`Prover::prove`] consumes. It lives for one request.
pub struct WitnessData {
  body: Body,
  presentation: Presentation,
  results: Map<String, Json>,
  witness_ms: f64,
  /// v0.5: the first phase's time (`prebuild`), which a wallet can run while the consent screen
  /// is shown; part of witness_ms.
  prebuild_ms: Option<f64>,
  /// The heap held before the witness step, and the most it held during it (measure::Heap).
  heap_base: usize,
  witness_high: usize,
  /// What the witness step reports: its time, sizes and the public values it claims.
  pub summary: Json,
}

pub struct Prover {
  pair: ZkProverPair,
  pub circuits_sha256: [u8; 32],
  pub load_ms: f64,
  /// The v0.5 circuits (`nym-auth-zk`), loaded with the v0.4 ones.
  v5: v05::Loaded<v5::Prover>,
  /// The heap the loaded keys or circuits hold (measure::Heap; one load at a time).
  pub keys_mb: Option<f64>,
}

fn bad(e: impl std::fmt::Display) -> Refusal {
  Refusal::bad_credential(e.to_string())
}

fn verifying_key(key: &PublicKey) -> Result<VerifyingKey, String> {
  let point = [&[0x04][..], &key.x, &key.y].concat();
  VerifyingKey::from_sec1_bytes(&point).map_err(|e| format!("not a P-256 point: {e}"))
}

fn ecdsa(rs: &[u8; 64]) -> Result<EcdsaSignature, String> {
  EcdsaSignature::from_slice(rs).map_err(|e| format!("not an ECDSA signature: {e}"))
}

/// The registry's description of the circuits, for both sides' `info`: the same circuit id under
/// each rulebook version, with that version's artifact and public inputs.
pub fn circuit_info(sha256: &[u8; 32], v05_sha256: &[u8; 32]) -> Json {
  json!([
    {
      "system_id": CIRCUIT_ID,
      "proof_system": PROOF_SYSTEM,
      "rulebook": "0.4",
      "artifact": crate::circuit::ARTIFACT,
      "artifact_sha256": hex(sha256),
      "public_inputs": PUBLIC_INPUTS.iter().map(|(n, _, _)| *n).collect::<Vec<_>>(),
    },
    {
      "system_id": v05::circuit_id(),
      "proof_system": v5::PROOF_SYSTEM,
      "rulebook": "0.5",
      "artifact": v05::ARTIFACT,
      "artifact_sha256": hex(v05_sha256),
      "public_inputs": v05::PUBLIC_INPUTS.iter().map(|(n, _, _)| *n).collect::<Vec<_>>(),
    },
  ])
}

/// The public values a witness claims, by input, as the guide shows them: text for T, E and C,
/// hex for the rest. The tags and a_v exist only once the proof is made.
fn public_summary(p: &Public, nym: &[u8; 32]) -> Json {
  let mut q = [0u8; 64];
  q[..32].copy_from_slice(&p.issuer_key.x);
  q[32..].copy_from_slice(&p.issuer_key.y);
  Json::Array(
    [
      ("proof_time", vec![p.time.clone()]),
      ("age_check.ge", vec![p.earliest.clone()]),
      ("age_check.le", vec![p.cutoff.clone()]),
      ("pseudonym.verifier_input", vec![hex(&p.verifier_input)]),
      ("mac.tags", vec![]),
      ("mac.a_v", vec![]),
      ("results.nym", vec![hex(nym)]),
      ("issuer_key_set", vec![hex(&q[..32]), hex(&q[32..])]),
      ("session_transcript", vec![hex(&p.challenge)]),
    ]
    .into_iter()
    .map(|(name, values)| json!({ "name": name, "values": values }))
    .collect(),
  )
}

impl Prover {
  /// Reads the circuits in `dir` (`circuits/mdoc`).
  pub fn load(dir: &Path) -> Result<Self, String> {
    let _one = crate::measure::exclusive()?;
    let heap = Heap::start();
    let c = Circuits::load(dir)?;
    let (circuits_sha256, load_ms) = (c.sha256, c.load_ms);
    let pair = ZkProverPair::new(c);
    let v5 = v05::load_prover()?;
    Ok(Prover { pair, circuits_sha256, load_ms: load_ms + v5.load_ms, v5, keys_mb: mb(heap.held()) })
  }

  pub fn info(&self) -> Json {
    json!({
      "service": "prover",
      "implementation": format!("Longfellow: {RUNTIME}, nym-auth-circuits LFC2 mdoc circuits (v0.4) and nym-auth-zk bsc circuits (v0.5); Node addon"),
      "version": env!("CARGO_PKG_VERSION"),
      "stub": false,
      "circuits": circuit_info(&self.circuits_sha256, &self.v5.sha256),
      "load_ms": self.load_ms,
      "keys_mb": self.keys_mb,
      "threads": 1,
    })
  }

  /// Step 1: the device key signs DeviceAuthentication over the SessionTranscript of `handover`.
  pub fn sign(&self, input: &SignInput) -> Result<SignOutput, Refusal> {
    let t = Instant::now();
    if input.doc_type != DOC_TYPE {
      return Err(Refusal::unsupported_request(format!("docType {} is not {DOC_TYPE}", input.doc_type)));
    }
    let k = &input.device_key;
    if k.kty != "EC" || k.crv != "P-256" {
      return Err(bad("the device key is not a P-256 EC key"));
    }
    let d: [u8; 32] = unb64url("device_key.d", &k.d).map_err(bad)?.try_into().map_err(|_| bad("device_key.d is not 32 bytes"))?;
    let signing = SigningKey::from_bytes(&d.into()).map_err(|e| bad(format!("device_key.d: {e}")))?;
    let point = signing.verifying_key().to_encoded_point(false);
    let (x, y) = (point.x().ok_or_else(|| bad("no x"))?, point.y().ok_or_else(|| bad("no y"))?);
    if crate::b64url(x) != k.x || crate::b64url(y) != k.y {
      return Err(bad("device_key.x and y are not the public key of device_key.d"));
    }
    let transcript = input.handover.session_transcript().map_err(Refusal::bad_request)?;
    let message = handover::device_message(&transcript, DOC_TYPE);
    let signature: EcdsaSignature = signing.sign(&message);
    Ok(SignOutput {
      device_signature: hex(&signature.to_bytes()),
      challenge_digest: hex(&handover::challenge_digest(&transcript, DOC_TYPE)),
      session_transcript: hex(&transcript),
      metrics: json!({ "sign_ms": ms(t) }),
    })
  }

  /// Step 2: takes the credential apart, makes every holder-side check, and builds both vectors.
  pub fn witness(&self, input: &WitnessInput) -> Result<WitnessData, Refusal> {
    let t = Instant::now();
    let heap = Heap::start();
    // The circuit id names the circuits: v0.4's (circuits/mdoc, ssc) or v0.5's (nym-auth-zk, bsc),
    // each read under its own rulebook version.
    let v05_id = v05::circuit_id();
    let (circuit_id, needs) = if input.system_id == CIRCUIT_ID {
      (CIRCUIT_ID, Rulebook::V04)
    } else if input.system_id == v05_id {
      (v05_id.as_str(), Rulebook::V05)
    } else {
      return Err(Refusal::unsupported_circuit(format!("{} is neither {CIRCUIT_ID} nor {v05_id}", input.system_id)));
    };
    // The time of the proof (proof_time), read first: v0.5 computes an age range's bounds from its date.
    let now = dates::now().map_err(Refusal::bad_request)?;
    let rulebook = Rulebook::parse(input.rulebook.as_deref())?;
    if rulebook != needs {
      return Err(Refusal::unsupported_circuit(format!("{circuit_id} reads requests of another rulebook version")));
    }
    let s: Statement = statement_for(&input.request, &input.credential_query_id, &input.handover, rulebook, Some(now.date))?;
    if s.offered_ids.as_ref().is_some_and(|ids| !ids.iter().any(|id| id == circuit_id))
      || s.offered_systems.as_ref().is_some_and(|ps| !ps.iter().any(|p| p == PROOF_SYSTEM))
    {
      return Err(Refusal::unsupported_circuit("the request does not offer this circuit"));
    }
    if input.credential.format != "mso_mdoc" || input.credential.doctype != DOC_TYPE {
      return Err(bad(format!("the credential is not an mso_mdoc of {DOC_TYPE}")));
    }
    if rulebook == Rulebook::V05 {
      return self.witness_v05(input, &s, &now, t, heap);
    }
    let m = mdoc::parse(&input.credential.issuer_signed).map_err(bad)?;
    if m.doc_type != DOC_TYPE {
      return Err(bad(format!("the MSO's docType {} is not {DOC_TYPE}", m.doc_type)));
    }
    let signer = x509::parse(&m.document_signer).map_err(|e| bad(format!("x5chain: {e}")))?;
    let issuer_key = signer.key;
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(&m.r);
    rs[32..].copy_from_slice(&m.s);
    verifying_key(&issuer_key)
      .and_then(|vk| ecdsa(&rs).and_then(|sig| vk.verify(&m.signed, &sig).map_err(|e| e.to_string())))
      .map_err(|e| bad(format!("the issuer signature does not verify under the Document Signer's key: {e}")))?;
    if !m.digests_listed() {
      return Err(bad("the MSO does not list the items' digests"));
    }
    let seed: [u8; 16] = unhex("secret_seed", &input.secret_seed).map_err(bad)?;
    if crate::sha256(&seed) != m.ssc {
      return Err(bad("secret_seed does not open the credential's ssc"));
    }
    let device: [u8; 64] = unhex("device_signature", &input.device_signature).map_err(bad)?;
    verifying_key(&m.device_key)
      .and_then(|vk| {
        let sig = ecdsa(&device)?;
        vk.verify(&handover::device_message(&s.session_transcript, DOC_TYPE), &sig).map_err(|e| e.to_string())
      })
      .map_err(|e| bad(format!("the device signature does not verify under the credential's device key: {e}")))?;

    // Holder data against the request: validity now, and the birth date in [E, C].
    let (now_s, from_s, until_s) = (dates::unix(&now), dates::unix(&m.valid_from), dates::unix(&m.valid_until));
    if !(from_s <= now_s && now_s < until_s) {
      return Err(Refusal::unsatisfiable(format!(
        "the credential is valid from {} until {}, not at {}",
        m.valid_from.text(),
        m.valid_until.text(),
        now.text()
      )));
    }
    if !s.age.holds(&m.birth_date) {
      return Err(Refusal::unsatisfiable("the birth date lies outside the requested range"));
    }

    let public = Public {
      time: now.text(),
      earliest: s.age.earliest(),
      cutoff: s.age.cutoff(),
      verifier_input: s.verifier_input,
      issuer_key,
      challenge: s.challenge,
    };
    let private = Private { mdoc: &m, secret_seed: seed, device_signature: device };
    let w = witness::witness(&self.pair.layout, &public, &private).map_err(|e| bad(format!("witness: {e}")))?;
    let nym = w.nym;
    let witness_ms = ms(t);

    let mut results = Map::new();
    let mut result_values = vec![(s.nym_handle.clone(), ResultValue::Pseudonym(nym))];
    results.insert(s.nym_handle.clone(), Json::String(hex(&nym)));
    if let Some(h) = &s.age_handle {
      result_values.push((h.clone(), ResultValue::True));
      results.insert(h.clone(), Json::Bool(true));
    }
    let l = &self.pair.layout;
    let summary = json!({
      "proof_time": now.text(),
      "results": results,
      "public_inputs": public_summary(&public, &nym),
      "counts": {
        "hash": { "inputs": l.hash.ninputs, "public": l.hash.npub },
        "signature": { "inputs": l.sig.ninputs, "public": l.sig.npub },
      },
      "metrics": { "witness_ms": witness_ms, "heap_mb": mb(heap.high() - heap.base()) },
    });
    Ok(WitnessData {
      body: Body::V04 { witness: w, transcript_seed: s.session_transcript.clone() },
      prebuild_ms: None,
      presentation: Presentation {
        system_id: CIRCUIT_ID.into(),
        proof: Vec::new(),
        issuer_key_set: vec![m.document_signer.clone()],
        proof_time: now.text(),
        results: result_values,
      },
      results,
      witness_ms,
      heap_base: heap.base(),
      witness_high: heap.high(),
      summary,
    })
  }

  /// Step 3: proves both circuits from the witness, and encodes the presentation.
  pub fn prove(&self, w: WitnessData) -> Result<Json, String> {
    let peak = Peak::start();
    let heap = Heap::start();
    let t = Instant::now();
    let proved = match w.body {
      Body::V04 { witness, transcript_seed } => self.pair.prove(witness, &transcript_seed)?,
      Body::V05 { prebuilt, device_signature } => {
        let p = self
          .v5
          .side
          .prove_prebuilt(prebuilt, &device_signature, &mut runtime_random::SecureRandomEngine::new())
          .map_err(|e| format!("the v0.5 circuits: {e:?}"))?;
        let rest = p.proof.len().saturating_sub(96);
        let parts = json!([
          { "name": "MAC tags (6)", "bytes": 96, "children": [] },
          { "name": "Hash and signature circuit proofs", "bytes": rest, "children": [] },
        ]);
        crate::zk::Proved { proof: p.proof, nym: p.pseudonym, parts }
      }
    };
    let prove_ms = ms(t);
    let peak_mb = peak.read();
    // The proof's working memory: the most the witness and prove steps held at once, above what
    // was held before the witness step (the witness itself stays held between the two).
    let heap_mb = mb(heap.high().max(w.witness_high).saturating_sub(w.heap_base));
    let proof_bytes = proved.proof.len();
    let system_id = w.presentation.system_id.clone();
    let presentation = Presentation { proof: proved.proof, ..w.presentation }.encode()?;
    Ok(json!({
      "system_id": system_id,
      "presentation": crate::b64url(&presentation),
      "results": w.results,
      "metrics": {
        "load_ms": self.load_ms,
        "keys_mb": self.keys_mb,
        "witness_ms": w.witness_ms,
        "prebuild_ms": w.prebuild_ms,
        "prove_ms": prove_ms,
        "total_ms": ((w.witness_ms + prove_ms) * 1e3).round() / 1e3,
        "heap_mb": heap_mb,
        // The witness held from the witness step into the prove step (part of heap_mb).
        "witness_mb": mb(heap.base().saturating_sub(w.heap_base)),
        "peak_memory_mb": peak_mb,
        "proof_bytes": proof_bytes,
        "proof_parts": proved.parts,
        "presentation_bytes": presentation.len(),
        "threads": 1,
      },
    }))
  }
}

impl Prover {
  /// Step 2 under rulebook v0.5 (the circuit `v05::circuit_id()`): the device signature, then the
  /// crate's first phase, `prebuild`, which makes the holder-side checks with their reasons
  /// (INTEGRATION.md §6: the issuer signature, the opening of bsc, validity at proof_time, the birth
  /// date's form and range), builds the hash circuit's witness and commits it. A wallet can run
  /// `prebuild` while the consent screen is shown, before the device signs; the demo phone signs
  /// first, so this step checks the signature here for a refusal with its reason, and reports
  /// `prebuild` apart (`prebuild_ms`, the Benchmark's "Prebuild (consent)").
  fn witness_v05(&self, input: &WitnessInput, s: &Statement, now: &dates::Time, t: Instant, heap: Heap) -> Result<WitnessData, Refusal> {
    let issuer_signed = unb64url("issuer_signed", &input.credential.issuer_signed).map_err(bad)?;
    let c = v05::credential(&issuer_signed).map_err(bad)?;
    let signer = x509::parse(&c.document_signer).map_err(|e| bad(format!("x5chain: {e}")))?;
    let seed: [u8; 16] = unhex("secret_seed", &input.secret_seed).map_err(bad)?;
    let birth_text = input.birth_date.as_deref().ok_or_else(|| bad("v0.5: birth_date is required (it opens bsc)"))?;
    let birth_date: [u8; 10] = birth_text.as_bytes().try_into().map_err(|_| bad("birth_date is not 10 bytes"))?;
    let device: [u8; 64] = unhex("device_signature", &input.device_signature).map_err(bad)?;
    let device_key = PublicKey { x: c.parsed.device_x, y: c.parsed.device_y };
    verifying_key(&device_key)
      .and_then(|vk| {
        let sig = ecdsa(&device)?;
        vk.verify(&handover::device_message(&s.session_transcript, DOC_TYPE), &sig).map_err(|e| e.to_string())
      })
      .map_err(|e| bad(format!("the device signature does not verify under the credential's device key: {e}")))?;
    let request = bsc::request(&signer.key, &now.text(), &input.request, &input.credential_query_id, &input.handover).map_err(Refusal::bad_request)?;
    let statement = request.statement().map_err(|e| Refusal::bad_request(format!("{e:?}")))?;
    let holder = v5::Holder { credential: &issuer_signed, secret_seed: seed, birth_date };
    let tp = Instant::now();
    let prebuilt = self.v5.side.prebuild(&request, &holder, &mut runtime_random::SecureRandomEngine::new()).map_err(|e| bsc::prover_refusal(&e))?;
    let prebuild_ms = ms(tp);
    let nym = prebuilt.pseudonym();
    let witness_ms = ms(t);

    let mut results = Map::new();
    results.insert(s.nym_handle.clone(), Json::String(hex(&nym)));
    let mut q = [0u8; 64];
    q[..32].copy_from_slice(&signer.key.x);
    q[32..].copy_from_slice(&signer.key.y);
    let public: Vec<Json> = [
      ("doctype", vec![DOC_TYPE.to_string()]),
      ("proof_time", vec![now.text()]),
      ("pseudonym.verifier_input", vec![hex(&statement.verifier_input)]),
      ("results.nym", vec![hex(&nym)]),
      ("age_check.ge", vec![s.age.earliest()]),
      ("age_check.le", vec![s.age.cutoff()]),
      ("mac.challenge", vec![]),
      ("mac.tags", vec![]),
      ("issuer_key_set", vec![hex(&q[..32]), hex(&q[32..])]),
      ("session_transcript", vec![hex(&statement.device_digest)]),
    ]
    .into_iter()
    .map(|(name, values)| json!({ "name": name, "values": values }))
    .collect();
    let summary = json!({
      "proof_time": now.text(),
      "rulebook": "0.5",
      "results": results,
      "public_inputs": public,
      "counts": { "hash": { "public": 278 }, "signature": { "public": 1155 } },
      "metrics": { "witness_ms": witness_ms, "prebuild_ms": prebuild_ms, "heap_mb": mb(heap.high() - heap.base()) },
    });
    Ok(WitnessData {
      body: Body::V05 { prebuilt, device_signature: device },
      presentation: Presentation {
        system_id: v05::circuit_id(),
        proof: Vec::new(),
        issuer_key_set: vec![c.document_signer.clone()],
        proof_time: now.text(),
        results: vec![(s.nym_handle.clone(), ResultValue::Pseudonym(nym))],
      },
      results,
      witness_ms,
      prebuild_ms: Some(prebuild_ms),
      heap_base: heap.base(),
      witness_high: heap.high(),
      summary,
    })
  }
}
