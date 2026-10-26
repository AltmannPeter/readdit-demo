//! The thread switch of `/tech`: a step runs on one thread, or on one per core. vega-prover and
//! vega-age parallelise with rayon (`rayon::join`, parallel iterators); a step run inside
//! [`pool`]`(parallel).install(…)` uses that pool's threads. Both pools are built once and kept.
//! The proof does not depend on the thread count.

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
    .thread_name(move |i| format!("vega-{threads}-{i}"))
    .build()
    .unwrap_or_else(|_| ThreadPoolBuilder::new().num_threads(1).build().expect("a one-thread pool"))
}

/// One thread, or one per core.
pub fn pool(parallel: bool) -> &'static ThreadPool {
  if parallel { ALL.get_or_init(|| build(cores())) } else { ONE.get_or_init(|| build(1)) }
}
