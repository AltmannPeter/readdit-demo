//! Spec 1.3–1.4 and 3.3.2: preserve validation before field conversion.
use bls12_381::{G1Projective, Scalar};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbsError {
    Invalid,
    Abort(&'static str),
}
pub const INVALID: BbsError = BbsError::Invalid;
pub type BbsResult<T> = Result<T, BbsError>;
impl std::fmt::Display for BbsError {
    /// Spec 1.3: distinguish INVALID from ABORT in diagnostics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid => f.write_str("INVALID"),
            Self::Abort(reason) => write!(f, "ABORT: {reason}"),
        }
    }
}
impl std::error::Error for BbsError {}

/// Spec 1.4.3: unreduced input, including r and 2^256 - 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalarInput(pub [u8; 32]);
impl ScalarInput {
    /// Spec 1.4.3: validate without reducing the input.
    pub fn to_scalar(self) -> BbsResult<Scalar> {
        let mut bytes = self.0;
        bytes.reverse();
        Option::<Scalar>::from(Scalar::from_bytes(&bytes)).ok_or(INVALID)
    }
}
impl From<Scalar> for ScalarInput {
    /// Spec 4.2.4.1: canonical field element in big-endian order.
    fn from(value: Scalar) -> Self {
        let mut bytes = value.to_bytes();
        bytes.reverse();
        Self(bytes)
    }
}
impl From<u64> for ScalarInput {
    /// Spec 1.4.3: represent a small scalar input without reduction.
    fn from(value: u64) -> Self {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Octets(Vec<u8>),
    Scalar(ScalarInput),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageType {
    OCTETS,
    SCALAR,
    Unknown(String),
}
pub use MessageType::{OCTETS, SCALAR};
/// Spec 3.3.2: disclosure states remain separate from message types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisclosureState {
    DISCLOSE,
    COMMIT,
    HIDE,
    Unknown(String),
}
pub use DisclosureState::{COMMIT, DISCLOSE, HIDE};

/// Spec 4.2.4.4: the eleven fields of a parsed proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub A_bar: G1Projective,
    pub B_bar: G1Projective,
    pub D: G1Projective,
    pub e_hat: ScalarInput,
    pub r1_hat: ScalarInput,
    pub r3_hat: ScalarInput,
    pub m_hats: Vec<ScalarInput>,
    pub N: u128,
    pub commitments: Vec<G1Projective>,
    pub s_hats: Vec<ScalarInput>,
    pub challenge: ScalarInput,
}

/// Spec 3.5.3: private witnesses; never include these in a presentation.
pub type AddZkpInfo = (Vec<ScalarInput>, Vec<ScalarInput>);
/// Spec 3.6.3: a proof and its prover-local commitment openings.
pub type ProofOutput = (Vec<u8>, AddZkpInfo);
/// Spec 4.1.3: precomputed commitments and their private openings.
pub type CommitmentOutput = (Vec<G1Projective>, Vec<ScalarInput>);

/// Spec 4.2.1: injectable scalar calls, including calls with count zero.
pub trait ScalarSource {
    /// Spec 4.2.1 calculate_random_scalars; implementations must advance between calls.
    fn calculate_random_scalars(&mut self, count: usize) -> BbsResult<Vec<ScalarInput>>;
}

/// Spec 4.2.1: operating-system randomness for normal operation.
pub struct OsRandom;
impl ScalarSource for OsRandom {
    /// Spec 4.2.1: reduce independent 48-byte OS samples.
    fn calculate_random_scalars(&mut self, count: usize) -> BbsResult<Vec<ScalarInput>> {
        crate::utils::calculate_random_scalars(count, &mut crate::utils::get_random)
    }
}
/// Spec 4.1.4 / Section 5: malformed indexes reach the predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Index {
    Integer(u64),
    Other(String),
}
impl From<u64> for Index {
    /// Spec 1.4.1: represent an integer index without sorting or coercion.
    fn from(value: u64) -> Self {
        Self::Integer(value)
    }
}
#[derive(Debug, Clone)]
pub struct Signature {
    pub A: G1Projective,
    pub e: ScalarInput,
}
#[derive(Debug, Clone)]
pub struct InitResult {
    pub A_bar: G1Projective,
    pub B_bar: G1Projective,
    pub D: G1Projective,
    pub T1: G1Projective,
    pub T2: G1Projective,
    pub domain: ScalarInput,
    pub C_tildes: Vec<G1Projective>,
}
