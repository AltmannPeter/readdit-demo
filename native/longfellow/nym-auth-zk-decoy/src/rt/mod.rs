#![cfg_attr(feature = "reference", allow(dead_code, unused_imports))]
//! Google's Longfellow ZK prover and verifier (google/longfellow-zk 61a8a73, Apache-2.0), with
//! their independent work run in parallel on the calling rayon pool (feature `parallel`, on by
//! default). Every output is Google's, byte for byte, at any thread count: the same random engine
//! gives the same commitment and proof, and the verifier the same verdict.

pub(crate) mod ligero;
pub(crate) mod par;
pub(crate) mod sumcheck;
pub(crate) mod zk;
