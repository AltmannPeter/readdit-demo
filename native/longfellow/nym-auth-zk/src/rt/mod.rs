//! Google's Longfellow ZK prover and verifier (longfellow-zk 61a8a73, `runtime_zk`,
//! `runtime_ligero`, `runtime_sumcheck`) with their independent work at once on rayon's pool:
//! the same commitments, proofs and verdicts as Google's, byte for byte, at any thread count.
//! Without the `parallel` feature everything runs in order on the calling thread.

mod ligero;
pub(crate) mod par;
mod sumcheck;
pub(crate) mod zk;

pub(crate) use ligero::{Barycentric, Interpolated};
