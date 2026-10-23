//! The circuits in Google's runtime, and the two-circuit protocol (SPEC.md L6), as the archive's
//! reference program runs it: Google's `run_mdoc_prover` and `run_mdoc_verifier` flow.
//!
//! The fields and interpolator factories are cheap to build, so each proof or verification builds
//! its own ([`with_runtime`]); the circuits are read once and kept.

use std::path::Path;
use std::time::Instant;

use core_algebra::SerializableField;
use core_proto::circuit::Circuit;
use core_proto::reader::CircuitReader;
use core_proto::FieldID;
use runtime_algebra::fp2::Fp2Field;
use runtime_algebra::gf2_128::Gf2_128Field;
use runtime_algebra::lch14_reed_solomon::Lch14InterpolatorFactory;
use runtime_algebra::p256::{P256Field, P256Subfield};
use runtime_algebra::reed_solomon::FftInterpolatorFactory;
use runtime_algebra::subfield::BinarySubfield;
use runtime_algebra::{ElementOf, SupportsFFT};
use runtime_ligero::param::LigeroConfig;
use runtime_random::{RandomEngine, SecureRandomEngine, Transcript};
use runtime_zk::common::ZkContext;
use runtime_zk::{ZkProof, ZkProver, ZkVerifier};
use sha2::{Digest, Sha256};

use crate::witness::{E16, E32, Layout, Public, Side, Witness, hash_public, set_mac_public, sig_public};

/// Ligero's parameters (L1): rate 1/7, 132 opened columns.
fn config(s: &Side) -> LigeroConfig {
  LigeroConfig { rateinv: 7, nreq: 132, block_enc: s.block_enc }
}

struct Fields {
  gf2: Gf2_128Field,
  sf_hash: BinarySubfield,
  p256: P256Field,
}

type HashCtx<'a> = ZkContext<'a, 2, Gf2_128Field, Lch14InterpolatorFactory<'a, 2, Gf2_128Field>>;
type SigCtx<'a> = ZkContext<'a, 4, P256Field, FftInterpolatorFactory<'a, 4, P256Field>>;

/// The runtime objects of one proof or verification.
struct Runtime<'a> {
  f: &'a Fields,
  h: &'a HashCtx<'a>,
  s: &'a SigCtx<'a>,
  sf_sig: &'a P256Subfield<'a>,
}

fn with_runtime<R>(body: impl FnOnce(&Runtime) -> R) -> R {
  let f = Fields {
    gf2: Gf2_128Field::new(),
    sf_hash: BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1),
    p256: P256Field::new(),
  };
  let p256_2 = Fp2Field::new(&f.p256);
  let mi_sig = FftInterpolatorFactory::new(&f.p256, &p256_2, p256_2.omega(), p256_2.omega_order());
  let mi_hash = Lch14InterpolatorFactory::new(&f.gf2, &f.sf_hash);
  let sf_sig = P256Subfield::new(&f.p256);
  let h = ZkContext { f: &f.gf2, make_interpolator: &mi_hash };
  let s = ZkContext { f: &f.p256, make_interpolator: &mi_sig };
  body(&Runtime { f: &f, h: &h, s: &s, sf_sig: &sf_sig })
}

fn elements<F: SerializableField>(f: &F, xs: &[impl AsRef<[u8]>]) -> Result<Vec<ElementOf<F>>, String> {
  xs.iter().map(|x| f.bytes_to_element(x.as_ref()).map_err(|_| "a value that is not a field element".to_string())).collect()
}

/// The circuits as data, read and checked against `params.tsv`.
pub struct Circuits {
  pub layout: Layout,
  /// SHA-256 of `circuits.zst`, which the registry pins.
  pub sha256: [u8; 32],
  pub load_ms: f64,
  sig: Circuit<P256Field>,
  hash: Circuit<Gf2_128Field>,
}

fn matches<F: SerializableField>(c: &Circuit<F>, s: &Side, name: &str) -> Result<(), String> {
  let r = &c.raw;
  if (r.ninput, r.npublic_input, r.subfield_boundary) != (s.ninputs, s.npub, s.subfield_boundary) || c.id != s.circuit_id {
    return Err(format!("the {name} circuit in circuits.zst is not the one params.tsv describes"));
  }
  Ok(())
}

impl Circuits {
  /// Reads `circuits.zst` in `dir`: the signature circuit, then the hash circuit (L6.1).
  pub fn load(dir: &Path) -> Result<Self, String> {
    let t = Instant::now();
    let layout = Layout::read(dir)?;
    let path = dir.join(crate::circuit::ARTIFACT);
    let zst = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let sha256: [u8; 32] = Sha256::digest(&zst).into();
    let pair = zstd::decode_all(&zst[..]).map_err(|e| format!("{}: zstd: {e}", path.display()))?;
    let (p256, gf2) = (P256Field::new(), Gf2_128Field::new());
    let (sig, rest) =
      CircuitReader::new(&p256, FieldID::P256).from_bytes(&pair, true).map_err(|e| format!("the signature circuit: {e:?}"))?;
    let (hash, rest) =
      CircuitReader::new(&gf2, FieldID::Gf2_128).from_bytes(rest, true).map_err(|e| format!("the hash circuit: {e:?}"))?;
    if !rest.is_empty() {
      return Err("circuits.zst: bytes after the hash circuit".into());
    }
    matches(&sig, &layout.sig, "signature")?;
    matches(&hash, &layout.hash, "hash")?;
    Ok(Circuits { layout, sha256, load_ms: crate::measure::ms(t), sig, hash })
  }
}

/// The prover side of both circuits.
pub struct ZkProverPair {
  pub layout: Layout,
  hash: ZkProver<2, Gf2_128Field>,
  sig: ZkProver<4, P256Field>,
}

/// What a proof is: the bytes (tags ‖ hash proof ‖ signature proof), the pseudonym it reveals,
/// and the bytes of each part (`/tech`).
pub struct Proved {
  pub proof: Vec<u8>,
  pub nym: [u8; 32],
  pub parts: serde_json::Value,
}

/// The bytes of one circuit's proof by part, as `ZkProof::write_to_buf` lays them out: the
/// commitment's Merkle root, the sumcheck transcript, then Ligero's proof (the blinding rows, the
/// column nonces, the opened columns, the Merkle path).
macro_rules! circuit_parts {
  ($name:expr, $p:expr, $g:expr, $f:expr, $sf:expr) => {{
    let mut sc = Vec::new();
    $p.sumcheck_proof.write_to_buf(&mut sc, &$g.sc_geom, $f).map_err(|e| format!("sizing the sumcheck: {e}"))?;
    let mut lg = Vec::new();
    $p.com_proof.write_to_buf(&mut lg, &$g.com_geom, $f, $sf).map_err(|e| format!("sizing Ligero's proof: {e}"))?;
    let c = &$p.com_proof;
    let rows = (c.y_ldt.len() + c.y_dot.len() + c.y_quad_0.len() + c.y_quad_2.len()) * $f.serialized_size_bytes();
    let nonces = c.merkle.nonce.len() * 32;
    let path = 4 + c.merkle.path.len() * 32;
    let columns = lg.len().saturating_sub(rows + nonces + path);
    serde_json::json!({ "name": $name, "bytes": 32 + sc.len() + lg.len(), "children": [
      { "name": "Commitment (Merkle root)", "bytes": 32, "children": [] },
      { "name": format!("Sumcheck ({} layers)", $p.sumcheck_proof.layers.len()), "bytes": sc.len(), "children": [] },
      { "name": "Ligero blinding rows", "bytes": rows, "children": [] },
      { "name": format!("Column nonces ({})", c.merkle.nonce.len()), "bytes": nonces, "children": [] },
      { "name": format!("Opened columns ({})", c.merkle.nonce.len()), "bytes": columns, "children": [] },
      { "name": format!("Merkle path ({} hashes)", c.merkle.path.len()), "bytes": path, "children": [] },
    ] })
  }};
}

impl ZkProverPair {
  pub fn new(c: Circuits) -> Self {
    let (hc, sc) = (config(&c.layout.hash), config(&c.layout.sig));
    ZkProverPair { layout: c.layout, hash: ZkProver::new(c.hash, hc), sig: ZkProver::new(c.sig, sc) }
  }

  /// L6.2: draws a_p, commits to both circuits on one transcript seeded with `transcript_seed`,
  /// derives a_v, writes the tags, and proves both.
  pub fn prove(&self, mut w: Witness, transcript_seed: &[u8]) -> Result<Proved, String> {
    let l = &self.layout;
    let (hpub, spub) = (l.hash.npub, l.sig.npub);
    with_runtime(|rt| {
      let mut rng = SecureRandomEngine::new();
      w.set_ap(l, std::array::from_fn(|_| rng.u128()));
      let wh = elements(&rt.f.gf2, &w.h[hpub..])?;
      let ws = elements(&rt.f.p256, &w.s[spub..])?;
      let mut tp = Transcript::new(transcript_seed);
      let (ch, gh) = self.hash.commit(&wh, rt.h, &mut tp, &mut rng, &rt.f.sf_hash);
      let (cs, gs) = self.sig.commit(&ws, rt.s, &mut tp, &mut rng, rt.sf_sig);
      let av = tp.u128();
      let tags = w.set_av(l, av);
      let proof_h = self
        .hash
        .prove(elements(&rt.f.gf2, &w.h[..hpub])?, wh, &ch, &mut tp, rt.h)
        .map_err(|e| format!("the hash circuit is not satisfied: {e}"))?;
      let proof_s = self
        .sig
        .prove(elements(&rt.f.p256, &w.s[..spub])?, ws, &cs, &mut tp, rt.s)
        .map_err(|e| format!("the signature circuit is not satisfied: {e}"))?;
      let mut out = Vec::new();
      for tag in tags {
        out.extend_from_slice(&tag.to_le_bytes());
      }
      proof_h.write_to_buf(&mut out, &gh, &rt.f.gf2, &rt.f.sf_hash).map_err(|e| format!("writing the hash proof: {e}"))?;
      proof_s.write_to_buf(&mut out, &gs, &rt.f.p256, rt.sf_sig).map_err(|e| format!("writing the signature proof: {e}"))?;
      let parts = serde_json::json!([
        { "name": "MAC tags (6)", "bytes": 96, "children": [] },
        circuit_parts!("Hash circuit (GF(2^128))", proof_h, gh, &rt.f.gf2, &rt.f.sf_hash),
        circuit_parts!("Signature circuit (P-256)", proof_s, gs, &rt.f.p256, rt.sf_sig),
      ]);
      Ok(Proved { proof: out, nym: w.nym, parts })
    })
  }
}

/// The verifier side of both circuits.
pub struct ZkVerifierPair {
  pub layout: Layout,
  hash: ZkVerifier<2, Gf2_128Field>,
  sig: ZkVerifier<4, P256Field>,
}

/// Why a proof is refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
  /// The bytes are not two proofs of these circuits' geometry after the 6 tags.
  Encoding(String),
  /// A circuit's proof does not verify with these public inputs.
  Invalid(&'static str),
}

impl ZkVerifierPair {
  pub fn new(c: Circuits) -> Self {
    let (hc, sc) = (config(&c.layout.hash), config(&c.layout.sig));
    ZkVerifierPair { layout: c.layout, hash: ZkVerifier::new(c.hash, hc), sig: ZkVerifier::new(c.sig, sc) }
  }

  /// L6.3: reads the tags and both proofs, replays both commitments on the transcript, derives
  /// a_v, and verifies both circuits against the verifier's own public values and the pseudonym.
  pub fn verify(&self, proof: &[u8], p: &Public, nym: &[u8; 32], transcript_seed: &[u8]) -> Result<(), Rejection> {
    let l = &self.layout;
    if proof.len() < 96 {
      return Err(Rejection::Encoding("shorter than the 6 tags".into()));
    }
    with_runtime(|rt| {
      let mut rest = &proof[96..];
      let ph = ZkProof::read(&mut rest, &self.hash.geometry(rt.h), &rt.f.gf2, &rt.f.sf_hash)
        .map_err(|e| Rejection::Encoding(format!("the hash proof: {e:?}")))?;
      let ps = ZkProof::read(&mut rest, &self.sig.geometry(rt.s), &rt.f.p256, rt.sf_sig)
        .map_err(|e| Rejection::Encoding(format!("the signature proof: {e:?}")))?;
      if !rest.is_empty() {
        return Err(Rejection::Encoding(format!("{} bytes after the signature proof", rest.len())));
      }
      let mut tp = Transcript::new(transcript_seed);
      self.hash.recv_commitment(&ph, &mut tp, rt.h);
      self.sig.recv_commitment(&ps, &mut tp, rt.s);
      let av_bytes: [u8; 16] = tp.bytes(16).try_into().map_err(|_| Rejection::Encoding("a_v".into()))?;
      let av = u128::from_le_bytes(av_bytes);
      let tags: [u128; 6] = std::array::from_fn(|k| {
        let mut t = [0u8; 16];
        t.copy_from_slice(&proof[16 * k..16 * k + 16]);
        u128::from_le_bytes(t)
      });
      let mut h: Vec<E16> = hash_public(l, p).map_err(Rejection::Encoding)?;
      let mut s: Vec<E32> = sig_public(l, p);
      set_mac_public(l, &mut h, &mut s, &tags, av, nym);
      let hv = elements(&rt.f.gf2, &h).map_err(Rejection::Encoding)?;
      let sv = elements(&rt.f.p256, &s).map_err(Rejection::Encoding)?;
      self.hash.verify(hv, &ph, &mut tp, rt.h).map_err(|_| Rejection::Invalid("hash"))?;
      self.sig.verify(sv, &ps, &mut tp, rt.s).map_err(|_| Rejection::Invalid("signature"))?;
      Ok(())
    })
  }
}
