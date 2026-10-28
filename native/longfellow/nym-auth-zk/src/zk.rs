//! The two circuits and their proofs on Google's Longfellow runtime, composed as Google's mdoc
//! presentations are (`mdoc_zk` v7, `run_mdoc_prover` / `run_mdoc_verifier`): one Fiat-Shamir
//! transcript; the hash circuit's Ligero commitment, then the signature circuit's; the MAC
//! challenge drawn from the transcript; then the hash proof and the signature proof, each
//! absorbing its circuit and public inputs. The proof bytes are Google's `MdocProof` layout: the
//! six MAC tags (16 bytes each, little-endian), the hash circuit's `ZkProof`, the signature
//! circuit's.

use core_algebra::SerializableField;
use core_proto::circuit::{Circuit, FieldID};
use core_proto::reader::CircuitReader;
use runtime_algebra::{
    fp2::Fp2Field, gf2_128::Gf2_128Field, lch14_reed_solomon::Lch14InterpolatorFactory,
    p256::{P256Field, P256Subfield}, reed_solomon::FftInterpolatorFactory, subfield::BinarySubfield,
    ElementOf, SupportsFFT,
};
use runtime_ligero::param::LigeroConfig;
use runtime_proto::ZkProof;
use runtime_random::{RandomEngine, Transcript};
use runtime_zk::{common::ZkContext, ZkProver, ZkVerifier};

use crate::Error;

/// The circuits as shipped: a zstd-compressed LFA2 archive with the entries "hash" (GF(2^128))
/// and "sig" (P-256's base field), each an LFC2 circuit whose id is Longfellow's own.
pub const CIRCUITS: &[u8] = include_bytes!("../circuits/nym_auth_mdoc_bsc.lfa2.zst");

/// The circuits' Longfellow ids (SHA-256 over their canonical encoding, `compute_id`).
pub const HASH_CIRCUIT_ID: &str = include_str!("../circuits/hash.id");
pub const SIG_CIRCUIT_ID: &str = include_str!("../circuits/sig.id");

/// The Ligero parameters each circuit is proved with (inverse rate 7, 132 opened columns, as
/// Google's mdoc circuits; the encoding block chosen for the circuit).
pub const HASH_LIGERO: LigeroConfig = LigeroConfig { rateinv: 7, nreq: 132, block_enc: 5111 };
pub const SIG_LIGERO: LigeroConfig = LigeroConfig { rateinv: 7, nreq: 132, block_enc: 3959 };

/// The transcript's domain: what the Fiat-Shamir transcript starts from, before the session's
/// device digest.
pub const TRANSCRIPT_DOMAIN: &[u8] = b"nym_auth/v1/mdoc-bsc/longfellow";

/// The two circuits, loaded.
pub struct Circuits {
    pub hash: Circuit<Gf2_128Field>,
    pub sig: Circuit<P256Field>,
}

/// The prover's side: Google's ZK provers over the two circuits.
pub struct Prover {
    hash: ZkProver<2, Gf2_128Field>,
    sig: ZkProver<4, P256Field>,
}

/// The verifier's side: Google's ZK verifiers over the two circuits.
pub struct Verifier {
    hash: ZkVerifier<2, Gf2_128Field>,
    sig: ZkVerifier<4, P256Field>,
}

impl Prover {
    pub fn new(c: Circuits) -> Prover {
        Prover { hash: ZkProver::new(c.hash, HASH_LIGERO), sig: ZkProver::new(c.sig, SIG_LIGERO) }
    }
    /// The shipped circuits' prover.
    pub fn load() -> Result<Prover, Error> {
        Ok(Prover::new(Circuits::load()?))
    }
}

impl Verifier {
    pub fn new(c: Circuits) -> Verifier {
        Verifier { hash: ZkVerifier::new(c.hash, HASH_LIGERO), sig: ZkVerifier::new(c.sig, SIG_LIGERO) }
    }
    /// The shipped circuits' verifier.
    pub fn load() -> Result<Verifier, Error> {
        Ok(Verifier::new(Circuits::load()?))
    }
}

fn hex32(s: &str) -> [u8; 32] {
    let s = s.trim();
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex id");
    }
    out
}

impl Circuits {
    /// The shipped circuits, each checked against its Longfellow id.
    pub fn load() -> Result<Circuits, Error> {
        Self::from_archive(CIRCUITS)
    }

    /// Circuits from a zstd-compressed LFA2 archive (entries "hash" and "sig"), each circuit's id
    /// recomputed and required equal to the expected one.
    pub fn from_archive(compressed: &[u8]) -> Result<Circuits, Error> {
        let raw = zstd::decode_all(compressed).map_err(|_| Error::Circuit("zstd"))?;
        let archive = core_proto::archive::CircuitArchive::from_bytes(&raw)
            .map_err(|_| Error::Circuit("not an LFA2 archive"))?;
        let gf2 = Gf2_128Field::new();
        let p256 = P256Field::new();
        let he = archive.get("hash").ok_or(Error::Circuit("no hash circuit"))?;
        let se = archive.get("sig").ok_or(Error::Circuit("no sig circuit"))?;
        let (hash, rest) = CircuitReader::new(&gf2, FieldID::Gf2_128)
            .from_bytes(&he.payload, true)
            .map_err(|_| Error::Circuit("hash circuit"))?;
        if !rest.is_empty() || hash.id != hex32(HASH_CIRCUIT_ID) || he.circuit_id != hash.id {
            return Err(Error::Circuit("hash circuit id"));
        }
        let (sig, rest) = CircuitReader::new(&p256, FieldID::P256)
            .from_bytes(&se.payload, true)
            .map_err(|_| Error::Circuit("sig circuit"))?;
        if !rest.is_empty() || sig.id != hex32(SIG_CIRCUIT_ID) || se.circuit_id != sig.id {
            return Err(Error::Circuit("sig circuit id"));
        }
        Ok(Circuits { hash, sig })
    }
}

/// The fields, subfields and interpolators Google's runtime proves with.
struct Fields {
    gf2: Gf2_128Field,
    sf_hash: BinarySubfield,
    p256: P256Field,
}

impl Fields {
    fn new() -> Fields {
        Fields {
            gf2: Gf2_128Field::new(),
            sf_hash: BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1),
            p256: P256Field::new(),
        }
    }
}

fn gf_elts(f: &Gf2_128Field, xs: &[u128]) -> Vec<ElementOf<Gf2_128Field>> {
    xs.iter()
        .map(|x| f.bytes_to_element(&x.to_le_bytes()).expect("GF(2^128) element"))
        .collect()
}

fn p_elts(f: &P256Field, xs: &[[u8; 32]]) -> Result<Vec<ElementOf<P256Field>>, Error> {
    xs.iter()
        .map(|x| f.bytes_to_element(x).map_err(|_| Error::Request("not a P-256 element")))
        .collect()
}

/// What the prover needs once it has committed: computes the public inputs from the MAC
/// challenge.
pub(crate) struct ProverInputs<'a> {
    pub hash_private: Vec<u128>,
    pub sig_private: Vec<[u8; 32]>,
    pub publics: &'a dyn Fn(u128) -> (Vec<u128>, Vec<[u8; 32]>, [u128; 6]),
}

pub(crate) fn transcript_init(device_digest: &[u8; 32]) -> Vec<u8> {
    let mut v = TRANSCRIPT_DOMAIN.to_vec();
    v.extend_from_slice(device_digest);
    v
}

/// Commits, draws the MAC challenge, proves; returns the proof bytes.
pub(crate) fn prove<R: RandomEngine>(
    pv: &Prover,
    init: &[u8],
    inputs: ProverInputs<'_>,
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let fl = Fields::new();
    let p256_2 = Fp2Field::new(&fl.p256);
    let mi_sig = FftInterpolatorFactory::new(&fl.p256, &p256_2, p256_2.omega(), p256_2.omega_order());
    let mi_hash = Lch14InterpolatorFactory::new(&fl.gf2, &fl.sf_hash);
    let sf_sig = P256Subfield::new(&fl.p256);
    let ctx_hash = ZkContext { f: &fl.gf2, make_interpolator: &mi_hash };
    let ctx_sig = ZkContext { f: &fl.p256, make_interpolator: &mi_sig };

    let (ch, cs) = (&pv.hash.circuit, &pv.sig.circuit);
    let nh = ch.raw.ninput - ch.raw.npublic_input;
    let ns = cs.raw.ninput - cs.raw.npublic_input;
    if inputs.hash_private.len() != nh || inputs.sig_private.len() != ns {
        return Err(Error::Internal("witness length"));
    }
    let wh = gf_elts(&fl.gf2, &inputs.hash_private);
    let ws = p_elts(&fl.p256, &inputs.sig_private)?;

    let mut tp = Transcript::new(init);
    let (prover_hash, prover_sig) = (&pv.hash, &pv.sig);
    let (commit_hash, geom_hash) = prover_hash.commit(&wh, &ctx_hash, &mut tp, rng, &fl.sf_hash);
    let (commit_sig, geom_sig) = prover_sig.commit(&ws, &ctx_sig, &mut tp, rng, &sf_sig);

    let challenge = tp.u128();
    let (ph, ps, tags) = (inputs.publics)(challenge);
    if ph.len() != ch.raw.npublic_input - 1 || ps.len() != cs.raw.npublic_input - 1 {
        return Err(Error::Internal("public input length"));
    }
    // The input layer's slot 0 is the constant 1, which the public inputs begin with.
    let mut pub_hash = vec![1u128];
    pub_hash.extend_from_slice(&ph);
    let mut one = [0u8; 32];
    one[0] = 1;
    let mut pub_sig = vec![one];
    pub_sig.extend_from_slice(&ps);

    let proof_hash = prover_hash
        .prove(gf_elts(&fl.gf2, &pub_hash), wh, &commit_hash, &mut tp, &ctx_hash)
        .map_err(|_| Error::Unsatisfied)?;
    let proof_sig = prover_sig
        .prove(p_elts(&fl.p256, &pub_sig)?, ws, &commit_sig, &mut tp, &ctx_sig)
        .map_err(|_| Error::Unsatisfied)?;

    let mut out = Vec::with_capacity(330_000);
    for t in tags {
        out.extend_from_slice(&t.to_le_bytes());
    }
    proof_hash
        .write_to_buf(&mut out, &geom_hash, &fl.gf2, &fl.sf_hash)
        .map_err(|_| Error::Internal("proof encoding"))?;
    proof_sig
        .write_to_buf(&mut out, &geom_sig, &fl.p256, &sf_sig)
        .map_err(|_| Error::Internal("proof encoding"))?;
    Ok(out)
}

/// Reads the proof, replays the transcript and verifies both proofs. `publics` gives the public
/// inputs (without the constant 1) from the MAC challenge and the tags the proof carries.
pub(crate) fn verify(
    vf: &Verifier,
    init: &[u8],
    proof: &[u8],
    publics: &dyn Fn(u128, &[u128; 6]) -> (Vec<u128>, Vec<[u8; 32]>),
) -> Result<(), Error> {
    let fl = Fields::new();
    let p256_2 = Fp2Field::new(&fl.p256);
    let mi_sig = FftInterpolatorFactory::new(&fl.p256, &p256_2, p256_2.omega(), p256_2.omega_order());
    let mi_hash = Lch14InterpolatorFactory::new(&fl.gf2, &fl.sf_hash);
    let sf_sig = P256Subfield::new(&fl.p256);
    let ctx_hash = ZkContext { f: &fl.gf2, make_interpolator: &mi_hash };
    let ctx_sig = ZkContext { f: &fl.p256, make_interpolator: &mi_sig };

    let (verifier_hash, verifier_sig) = (&vf.hash, &vf.sig);
    let geom_hash = verifier_hash.geometry(&ctx_hash);
    let geom_sig = verifier_sig.geometry(&ctx_sig);

    if proof.len() < 96 {
        return Err(Error::Proof("too short"));
    }
    let mut tags = [0u128; 6];
    for (k, t) in tags.iter_mut().enumerate() {
        *t = u128::from_le_bytes(proof[16 * k..16 * k + 16].try_into().unwrap());
    }
    let mut rest = &proof[96..];
    let proof_hash = ZkProof::read(&mut rest, &geom_hash, &fl.gf2, &fl.sf_hash)
        .map_err(|_| Error::Proof("hash proof encoding"))?;
    let proof_sig = ZkProof::read(&mut rest, &geom_sig, &fl.p256, &sf_sig)
        .map_err(|_| Error::Proof("signature proof encoding"))?;
    if !rest.is_empty() {
        return Err(Error::Proof("trailing bytes"));
    }

    let mut tp = Transcript::new(init);
    verifier_hash.recv_commitment(&proof_hash, &mut tp, &ctx_hash);
    verifier_sig.recv_commitment(&proof_sig, &mut tp, &ctx_sig);
    let challenge = u128::from_le_bytes(tp.bytes(16).try_into().unwrap());
    let (ph, ps) = publics(challenge, &tags);
    if ph.len() != verifier_hash.circuit.raw.npublic_input - 1
        || ps.len() != verifier_sig.circuit.raw.npublic_input - 1
    {
        return Err(Error::Internal("public input length"));
    }
    let mut pub_hash = vec![1u128];
    pub_hash.extend_from_slice(&ph);
    let mut one = [0u8; 32];
    one[0] = 1;
    let mut pub_sig = vec![one];
    pub_sig.extend_from_slice(&ps);
    verifier_hash
        .verify(gf_elts(&fl.gf2, &pub_hash), &proof_hash, &mut tp, &ctx_hash)
        .map_err(|_| Error::Proof("hash proof does not verify"))?;
    verifier_sig
        .verify(p_elts(&fl.p256, &pub_sig)?, &proof_sig, &mut tp, &ctx_sig)
        .map_err(|_| Error::Proof("signature proof does not verify"))?;
    Ok(())
}

