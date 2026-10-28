//! The thread pools of `/tech`'s multithreading switch: one thread, or one per core, each built
//! once. The rulebook v0.5 circuits (`nym-auth-zk` 0.3.0) prove and verify on the pool they run in;
//! the v0.4 circuits run on Google's runtime directly, on one thread.

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

/// One thread, or one per core (`/tech`'s switch).
pub fn pool(parallel: bool) -> &'static ThreadPool {
  if parallel { ALL.get_or_init(|| build(cores())) } else { ONE.get_or_init(|| build(1)) }
}
