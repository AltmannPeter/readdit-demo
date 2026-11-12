//! Zero-knowledge presentations of the nym_auth mdoc attestation on Longfellow, for
//! **nym_auth rulebook v0.6**, whose credential is the **decoy-digest layout with the precomputed
//! prefix**.
//!
//! **The attestation** (ISO/IEC 18013-5 mdoc, docType and namespace
//! `eu.europa.ec.eudi.nym_auth.1`): the MSO's `valueDigests` hold `bsc` (digestID 0) and `psc`
//! (digestID 1) themselves, each a 32-byte commitment; `bsc = SHA-256(secret_seed || birth_date)`,
//! with the holder's 16-byte `secret_seed` and the 10-character `birth_date` (YYYY-MM-DD) kept
//! outside the credential. There are no IssuerSignedItems, and the 398-byte MSO has a fixed key
//! order, so the 423-byte Sig_structure has every field at a fixed offset ([`mdoc`]). `psc` is
//! signed but not read.
//!
//! **The statement**, one proof, nothing disclosed but the pseudonym:
//! - the issuer signed the Sig_structure under the verifier's issuer key (ECDSA P-256), its
//!   SHA-256 computed from the state after the constant first 128 bytes, every constant byte the
//!   template's;
//! - valid_from <= proof_time <= valid_until;
//! - the device key in the MSO signed the session (the verifier's challenge digest);
//! - the holder's (secret_seed, birth_date) opens bsc, and E <= birth_date <= C for the
//!   verifier's age range;
//! - the pseudonym is SHA-256("nym_auth/v1/known-offender-matching-ssc" || secret_seed || 0^32 ||
//!   verifier_input), verifier_input = SHA-256(verifier_id).
//!
//! **The proof system** is Longfellow (Ligero commitments and sumcheck, Google's runtime; the
//! prover's and verifier's independent work in parallel on the caller's rayon pool) on two
//! circuits: a hash circuit over GF(2^128) (the SHA-256 compressions, packed four bits per input
//! with Google's bit plucker, the date comparisons) and a signature circuit over P-256's base field
//! (both ECDSA verifications), tied by an affine MAC, t = a + c m, over the MSO digest and the
//! device key ([`zk`]).
//!
//! Prover: [`Prover::load`], [`Prover::prebuild`] during consent, [`Prover::device_signed_bytes`]
//! for the device key to sign, then [`Prover::prove_prebuilt`]. Verifier: [`Verifier::load`], then
//! [`Verifier::verify`]. Both use the rayon pool they run in ([`threads`]).

// `x % 4 == 0` keeps the crate building on Rust 1.85; the closures' types are spelled out once.
#![allow(unknown_lints, clippy::manual_is_multiple_of, clippy::type_complexity)]

pub mod cbor;
pub mod ecdsa;
pub mod gf;
pub mod mdoc;
pub mod request;
pub mod sha;
pub mod witness;
mod rt;
pub mod zk;

pub use request::{AgeRange, Date, Session};
pub use witness::Holder;
pub use zk::{threads, Circuits, Prover, Verifier};

use runtime_random::RandomEngine;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The credential cannot be parsed into what the circuits read.
    Credential(&'static str),
    /// A request value is malformed.
    Request(&'static str),
    /// The circuits cannot be loaded, or are not the expected ones.
    Circuit(&'static str),
    /// The holder's data does not satisfy the request, found by the checks before proving (a
    /// wrong opening, a birth date outside the range, a credential not valid at proof_time, a
    /// signature that does not verify). The reason is for the wallet's user, not the verifier.
    Holder(&'static str),
    /// The prover's inputs do not satisfy a circuit (what the checks before proving do not
    /// cover).
    Unsatisfied,
    /// The proof does not verify.
    Proof(&'static str),
    /// An inconsistency of this library.
    Internal(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// A presentation request, as both sides hold it.
#[derive(Clone, Debug)]
pub struct Request {
    /// The issuer's (Document Signer's) P-256 public key, x and y big-endian.
    pub issuer_key: ([u8; 32], [u8; 32]),
    /// proof_time, "YYYY-MM-DDThh:mm:ssZ" (UTC). A public input: the proof holds at this time.
    /// Whether the time is acceptable (the verifier's clock, within the rulebook's tolerance) is
    /// the verifier's check, outside the proof.
    pub proof_time: String,
    /// The age range ("A-B", "A+", "B-"); `None` takes the widest bounds.
    pub age_range: Option<AgeRange>,
    /// The pseudonym's verifier_id (its verifier_input is SHA-256(verifier_id)).
    pub verifier_id: String,
    /// The session the device signature binds.
    pub session: Session,
}

impl Request {
    /// The statement's public values.
    pub fn statement(&self) -> Result<witness::Statement, Error> {
        let (now, d) = request::proof_time(&self.proof_time)?;
        let (e, c) = match &self.age_range {
            Some(r) => r.bounds(d),
            None => (None, None),
        };
        let (born_from, born_by) = request::bound_numbers(e, c);
        let device = request::device_signed_bytes(&self.session, mdoc::DOC_TYPE);
        use sha2::{Digest, Sha256};
        Ok(witness::Statement {
            now,
            born_from,
            born_by,
            verifier_input: request::verifier_input(&self.verifier_id),
            issuer_x: self.issuer_key.0,
            issuer_y: self.issuer_key.1,
            device_digest: Sha256::digest(&device).into(),
        })
    }
}

/// The registry's system_id of the shipped circuits: `urn:circuits:sha256:` and the SHA-256 of
/// the circuit archive file as shipped ([`zk::CIRCUITS`], the zstd-compressed LFA2 bytes).
pub fn system_id() -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(zk::CIRCUITS);
    let mut s = String::from("urn:circuits:sha256:");
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The proof system of the registry entry (Google longfellow-zk 61a8a73, Ligero over sumcheck).
pub const PROOF_SYSTEM: &str = "longfellow-libzk-v1";

/// A presentation: the pseudonym (the statement's one output) and the proof bytes (Google's mdoc
/// proof layout: six MAC tags, the hash circuit's proof, the signature circuit's proof).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Presentation {
    pub pseudonym: [u8; 32],
    pub proof: Vec<u8>,
}

impl Prover {
    /// The bytes the device key signs for `request` (ECDSA P-256 with SHA-256): the detached
    /// COSE_Sign1's Sig_structure over DeviceAuthenticationBytes.
    pub fn device_signed_bytes(request: &Request) -> Vec<u8> {
        request::device_signed_bytes(&request.session, mdoc::DOC_TYPE)
    }

    /// Proves the statement for `request` with the holder's credential and secrets and the
    /// device signature (r || s) over [`Prover::device_signed_bytes`]. `rng` must be a CSPRNG
    /// (Google's `SecureRandomEngine`): it draws the MAC keys and the commitments' randomness.
    /// The same as [`Prover::prebuild`] then [`Prover::prove_prebuilt`].
    pub fn prove<R: RandomEngine>(
        &self,
        request: &Request,
        holder: &Holder,
        device_signature: &[u8; 64],
        rng: &mut R,
    ) -> Result<Presentation, Error> {
        let pre = self.prebuild(request, holder, rng)?;
        self.prove_prebuilt(pre, device_signature, rng)
    }

    /// Phase 1, before the device signature (while the consent screen shows): parses the
    /// credential, checks the holder's data against the request ([`Error::Holder`] with the
    /// reason), computes the statement, draws the MAC keys, builds the hash circuit's witness and
    /// commits it. This is most of the proving work.
    ///
    /// `request.proof_time` is fixed here: the verifier checks it against its clock within its
    /// tolerance, so finish within that tolerance or prebuild again. The result holds the
    /// holder's secrets and the commitment's randomness: it is consumed by
    /// [`Prover::prove_prebuilt`], cannot be copied, and should be dropped if the user declines.
    pub fn prebuild<R: RandomEngine>(&self, request: &Request, holder: &Holder, rng: &mut R) -> Result<Prebuilt, Error> {
        let st = request.statement()?;
        let parsed = mdoc::parse(holder.credential)?;
        witness::holder_checks(&parsed, holder, &st)?;
        let mut keys = [0u128; 6];
        for k in keys.iter_mut() {
            *k = rng.u128();
        }
        let nym = witness::pseudonym(&holder.secret_seed, &st.verifier_input);
        let hash_private = witness::hash_private(&parsed, holder, &st, &keys);
        let committed = zk::commit_hash(self, &zk::transcript_init(&st.device_digest), &hash_private, rng)?;
        Ok(Prebuilt { st, parsed, keys, nym, committed })
    }

    /// Phase 2, after the device key has signed [`Prover::device_signed_bytes`] of the same
    /// request: checks the signature ([`Error::Holder`]), builds the signature circuit's witness,
    /// commits it, draws the MAC challenge and proves both circuits.
    pub fn prove_prebuilt<R: RandomEngine>(
        &self,
        pre: Prebuilt,
        device_signature: &[u8; 64],
        rng: &mut R,
    ) -> Result<Presentation, Error> {
        let Prebuilt { st, parsed, keys, nym, committed } = pre;
        witness::device_check(&parsed, &st, device_signature)?;
        let sig_private = witness::sig_private(&parsed, &st, device_signature, &keys);
        let publics = |c: u128| {
            let tags = witness::mac_tags(&parsed, &keys, c);
            (witness::hash_public(&st, &nym, c, &tags), witness::sig_public(&st, c, &tags), tags)
        };
        let proof = zk::finish(self, committed, &sig_private, &publics, rng)?;
        Ok(Presentation { pseudonym: nym, proof })
    }
}

/// A presentation's first phase ([`Prover::prebuild`]): the statement, the parsed credential, the
/// MAC keys, the pseudonym, and the hash circuit's committed witness. It holds the holder's
/// secrets: it is not `Clone`, `Debug` prints nothing of it, and [`Prover::prove_prebuilt`]
/// consumes it.
pub struct Prebuilt {
    st: witness::Statement,
    parsed: mdoc::Parsed,
    keys: [u128; 6],
    nym: [u8; 32],
    committed: zk::HashCommitted,
}

impl Prebuilt {
    /// The pseudonym the presentation will carry.
    pub fn pseudonym(&self) -> [u8; 32] {
        self.nym
    }
}

impl std::fmt::Debug for Prebuilt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Prebuilt(..)")
    }
}

impl Verifier {
    /// Verifies `presentation` for `request`: Ok when both proofs verify for the statement and the
    /// presentation's pseudonym.
    pub fn verify(&self, request: &Request, presentation: &Presentation) -> Result<(), Error> {
        let st = request.statement()?;
        let publics = |c: u128, tags: &[u128; 6]| {
            (
                witness::hash_public(&st, &presentation.pseudonym, c, tags),
                witness::sig_public(&st, c, tags),
            )
        };
        zk::verify(
            self,
            &zk::transcript_init(&st.device_digest),
            &presentation.proof,
            &publics,
        )
    }
}
