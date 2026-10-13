//! The keys from the circuits as data (SPEC.md V1.1, V6): `shapes.zst` decompressed and replayed
//! through `app::setup_from_shapes_in`. Setup is deterministic, so both sides build the keys once
//! and keep them.

use std::path::Path;
use std::time::Instant;

use sha2::{Digest, Sha256};
use vega_age::app::{self, ProverKey, VerifierKey};

use crate::circuit::LAYOUT;

/// What a side loaded: the keys, the SHA-256 of the `shapes.zst` they come from, and how long
/// reading, decompressing and setup took.
pub struct Loaded<K> {
  pub key: K,
  pub shapes_sha256: [u8; 32],
  pub load_ms: f64,
}

fn read(path: &Path) -> Result<(Vec<u8>, [u8; 32]), String> {
  let zst = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
  let digest: [u8; 32] = Sha256::digest(&zst).into();
  let raw = zstd::stream::decode_all(&zst[..]).map_err(|e| format!("{}: zstd: {e}", path.display()))?;
  Ok((raw, digest))
}

/// The prover key from `shapes.zst`.
pub fn prover_key(path: &Path) -> Result<Loaded<ProverKey>, String> {
  let t = Instant::now();
  let (raw, shapes_sha256) = read(path)?;
  let (pk, vk) = app::setup_from_shapes_in(&LAYOUT, &raw).map_err(|e| format!("keys: {e:?}"))?;
  drop(vk);
  Ok(Loaded { key: pk, shapes_sha256, load_ms: crate::measure::ms(t) })
}

/// The verifier key from `shapes.zst`, its digest computed so that no verification pays for it.
pub fn verifier_key(path: &Path) -> Result<Loaded<VerifierKey>, String> {
  let t = Instant::now();
  let (raw, shapes_sha256) = read(path)?;
  let (pk, vk) = app::setup_from_shapes_in(&LAYOUT, &raw).map_err(|e| format!("keys: {e:?}"))?;
  drop(pk);
  vk.ready().map_err(|e| format!("verifier key digest: {e:?}"))?;
  Ok(Loaded { key: vk, shapes_sha256, load_ms: crate::measure::ms(t) })
}
