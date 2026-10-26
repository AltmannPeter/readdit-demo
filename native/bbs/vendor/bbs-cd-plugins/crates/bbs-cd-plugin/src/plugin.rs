//! Plugin interface.
//!
//! A plugin proves a statement about the values behind some ETSI commitments
//! D_j = m_j·Y0 + s_j·Y1 of one presentation.  The envelope gives it:
//!
//! * [`EnvContext`]: the request nonce, the request context `ctx` and the
//!   envelope statement `env` (which contains `ctx` and every credential's
//!   issuer, header, disclosed values, committed indexes and D_j);
//! * the committed inputs of its attribute (prover) or their commitments
//!   (verifier);
//! * its request parameters.
//!
//! **Binding rules** every plugin must follow (docs/ENVELOPE.md §5): its
//! Fiat–Shamir transcript includes its plugin id, `env` (or its digest), its
//! position `plugin_index`, its parameters, the nonce and every value it
//! reveals, under its own domain-separation tags.
use bbs_cd::types::ScalarInput;
use bls12_381::G1Projective;
pub use rand_core::CryptoRngCore;

use crate::error::Result;
use crate::schema::AttributeSpec;
use crate::transcript::sha256;

/// What every plugin proof is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvContext {
    pub nonce: Vec<u8>,
    pub ctx: Vec<u8>,
    /// Envelope statement (framework id, ctx, credential statements).
    pub env: Vec<u8>,
    /// Position of this plugin in `Request::plugins`.
    pub plugin_index: u16,
}

impl EnvContext {
    pub fn env_digest(&self) -> [u8; 32] {
        sha256(&self.env)
    }
}

/// One committed message as the holder knows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedMessage {
    /// BBS message index.
    pub index: u16,
    /// The committed value m_j (a SCALAR message).
    pub value: ScalarInput,
    /// The ETSI opening s_j.
    pub opening: ScalarInput,
    /// D_j = m_j·Y0 + s_j·Y1.
    pub commitment: G1Projective,
}

/// Prover-side input of a plugin: the committed messages of its attribute,
/// in message order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedInput {
    pub credential: usize,
    pub attribute: AttributeSpec,
    pub messages: Vec<CommittedMessage>,
}

/// Verifier-side view of the same attribute: indexes and commitments only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedView {
    pub credential: usize,
    pub attribute: AttributeSpec,
    pub indexes: Vec<u16>,
    pub commitments: Vec<G1Projective>,
}

impl CommittedInput {
    pub fn view(&self) -> CommittedView {
        CommittedView {
            credential: self.credential,
            attribute: self.attribute.clone(),
            indexes: self.messages.iter().map(|m| m.index).collect(),
            commitments: self.messages.iter().map(|m| m.commitment).collect(),
        }
    }
}

/// Verifier side of a plugin.  Registered with the envelope verifier by id.
pub trait PluginVerifier: Send + Sync {
    fn plugin_id(&self) -> &[u8];
    /// Verifier policy: may this plugin run on `attr` with `params`?
    fn check_request(&self, attr: &AttributeSpec, params: &[u8]) -> Result<()>;
    /// Verify one proof.  Returns the plugin's public output (empty if none).
    /// `rng` is verifier randomness (for example, batch weights).
    fn verify(
        &self,
        env: &EnvContext,
        view: &CommittedView,
        params: &[u8],
        proof: &[u8],
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>>;
}

/// Prover side of a plugin.  Holds the plugin's prepared (single-use) state
/// and is consumed by `prove`.
pub trait PluginProver {
    fn plugin_id(&self) -> &[u8];
    fn prove(
        self: Box<Self>,
        env: &EnvContext,
        input: &CommittedInput,
        params: &[u8],
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>>;
}
