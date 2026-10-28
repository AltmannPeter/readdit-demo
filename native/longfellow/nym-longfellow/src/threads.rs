//! The thread pools of `/tech`'s multithreading switch: one thread, or one per core, each built
//! once. The rulebook v0.5 circuits (`nym-auth-zk` 0.3.0) prove and verify on the pool they run in;
//! the v0.4 circuits run on Google's runtime directly, on one thread.
//!
//! An app that embeds this crate sizes the parallel pool for its device with [`set_threads`]
//! before its first proof (a wallet on a phone: its performance cores, not every core); the site
//! does not call it and gets one thread per core.

use std::sync::OnceLock;

use rayon::{ThreadPool, ThreadPoolBuilder};

static ONE: OnceLock<ThreadPool> = OnceLock::new();
static ALL: OnceLock<ThreadPool> = OnceLock::new();

/// The cores this machine offers.
pub fn cores() -> usize {
  std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

fn build(threads: usize) -> ThreadPool {
  ThreadPoolBuilder::new()
    .num_threads(threads)
    .thread_name(move |i| format!("longfellow-{threads}-{i}"))
    .build()
    .unwrap_or_else(|_| ThreadPoolBuilder::new().num_threads(1).build().expect("a one-thread pool"))
}

/// Sizes the parallel pool: `threads` (at least 1) instead of one per core. Only before the pool
/// is first used; returns the size the pool has.
pub fn set_threads(threads: usize) -> usize {
  ALL.get_or_init(|| build(threads.max(1))).current_num_threads()
}

/// One thread, or the parallel pool: one per core unless [`set_threads`] sized it (`/tech`'s switch).
pub fn pool(parallel: bool) -> &'static ThreadPool {
  if parallel { ALL.get_or_init(|| build(cores())) } else { ONE.get_or_init(|| build(1)) }
}
