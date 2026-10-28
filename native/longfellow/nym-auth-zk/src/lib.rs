//! Zero-knowledge presentations of the nym_auth mdoc attestation on Longfellow.
//!
//! **The attestation** (the nym_auth rulebook, ISO/IEC 18013-5 mdoc, compact profile): docType
//! and namespace `eu.europa.ec.eudi.nym_auth.1`, the items `bsc` (digestID 0) and `psc`
//! (digestID 1), each a 32-byte commitment; `bsc = SHA-256(secret_seed || birth_date)`, with the
//! holder's 16-byte `secret_seed` and the 10-character `birth_date` (YYYY-MM-DD) kept outside the
//! credential. `psc` is signed but not read.
//!
//! **The statement**, one proof, nothing disclosed but the pseudonym:
//! - the issuer signed the credential's MSO under the verifier's issuer key (ECDSA P-256), over
//!   the Sig_structure hashed whole from the SHA-256 initial value with its padding checked (the
//!   private length L, 0x80 at L, zeros, the length field 8L; the bsc item likewise), every read
//!   ending within the message;
//! - the MSO's docType is the requested one;
//! - valid_from <= proof_time <= valid_until;
//! - the device key in the MSO signed the session (the verifier's challenge digest);
//! - the holder's (secret_seed, birth_date) opens bsc, and E <= birth_date <= C for the
//!   verifier's age range;
//! - the pseudonym is SHA-256("nym_auth/v1/known-offender-matching-ssc" || secret_seed || 0^32 ||
//!   verifier_input), verifier_input = SHA-256(verifier_id).
//!
//! **The proof system** is Longfellow (Ligero commitments and sumcheck, Google's Rust runtime) on
//! two circuits: a hash circuit over GF(2^128) (the SHA-256 computations, the byte reads, the
//! date and time comparisons) and a signature circuit over P-256's base field (both ECDSA
//! verifications), tied by an affine MAC, t = a + c m, over the MSO digest and the device key,
//! composed as Google's mdoc presentations are ([`zk`]).
//!
//! Prover: [`Prover::load`], then [`Prover::device_signed_bytes`] for the device key to sign, then
//! [`Prover::prove`]. Verifier: [`Verifier::load`], then [`Verifier::verify`].

pub mod cbor;
pub mod ecdsa;
pub mod gf;
pub mod mdoc;
pub mod request;
pub mod sha;
pub mod witness;
pub mod zk;

pub use request::{AgeRange, Date, Session};
pub use witness::Holder;
pub use zk::{Circuits, Prover, Verifier};

use runtime_random::RandomEngine;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The credential cannot be parsed into what the circuits read.
    Credential(&'static str),
    /// A request value is malformed.
    Request(&'static str),
    /// The circuits cannot be loaded, or are not the expected ones.
    Circuit(&'static str),
    /// The prover's inputs do not satisfy the statement (a wrong opening, an age outside the
    /// range, an expired credential, a wrong signature...).
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
            doc_type: mdoc::DOC_TYPE.to_string(),
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
    pub fn prove<R: RandomEngine>(
        &self,
        request: &Request,
        holder: &Holder,
        device_signature: &[u8; 64],
        rng: &mut R,
    ) -> Result<Presentation, Error> {
        let st = request.statement()?;
        let parsed = mdoc::parse(holder.credential, &st.doc_type)?;
        let mut keys = [0u128; 6];
        for k in keys.iter_mut() {
            *k = rng.u128();
        }
        let nym = witness::pseudonym(&holder.secret_seed, &st.verifier_input);
        let hash_private = witness::hash_private(&parsed, holder, &st, &keys);
        let sig_private = witness::sig_private(&parsed, &st, device_signature, &keys);
        let publics = |c: u128| {
            let tags = witness::mac_tags(&parsed, &keys, c);
            (
                witness::hash_public(&st, &nym, c, &tags),
                witness::sig_public(&st, c, &tags),
                tags,
            )
        };
        let proof = zk::prove(
            self,
            &zk::transcript_init(&st.device_digest),
            zk::ProverInputs {
                hash_private,
                sig_private,
                publics: &publics,
            },
            rng,
        )?;
        Ok(Presentation {
            pseudonym: nym,
            proof,
        })
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
