//! The thread pools of `/tech`'s thread setting: one thread, one per core, or a count in between
//! ([`pool_of`]), each built once. The circuits of rulebooks v0.5 and v0.6 prove and verify on the
//! pool they run in; the v0.4 circuits run on Google's runtime directly, on one thread.
//!
//! An app that embeds this crate sizes the parallel pool for its device with [`set_threads`]
//! before its first proof (a wallet on a phone: its performance cores, not every core); the site
//! does not call it and gets one thread per core.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use rayon::{ThreadPool, ThreadPoolBuilder};

static ONE: OnceLock<ThreadPool> = OnceLock::new();
static ALL: OnceLock<ThreadPool> = OnceLock::new();
/// The pools of the counts in between, by count.
type Pools = Mutex<HashMap<usize, &'static ThreadPool>>;
static SIZED: OnceLock<Pools> = OnceLock::new();

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

/// The threads a step runs on: `threads` when given, clamped to 1..=[`cores`]; otherwise one, or
/// the parallel pool's size.
pub fn count(parallel: bool, threads: Option<usize>) -> usize {
  match threads {
    Some(n) => n.clamp(1, cores()),
    None => pool(parallel).current_num_threads(),
  }
}

/// The pool for a thread count from `/tech` (`threads`: 1 up to [`cores`]); without one, [`pool`].
/// A count other than 1 and the parallel pool's size gets its own pool, built once and kept.
pub fn pool_of(parallel: bool, threads: Option<usize>) -> &'static ThreadPool {
  let Some(n) = threads.map(|n| n.clamp(1, cores())) else { return pool(parallel) };
  if n == 1 {
    return pool(false);
  }
  if n == pool(true).current_num_threads() {
    return pool(true);
  }
  let mut sized = SIZED.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap_or_else(|e| e.into_inner());
  if let Some(p) = sized.get(&n).copied() {
    return p;
  }
  let p: &'static ThreadPool = Box::leak(Box::new(build(n)));
  sized.insert(n, p);
  p
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn a_count_picks_a_pool_of_that_size() {
    let n = cores();
    assert_eq!(pool_of(true, Some(1)).current_num_threads(), 1);
    assert_eq!(pool_of(false, Some(0)).current_num_threads(), 1);
    assert_eq!(pool_of(false, Some(n + 7)).current_num_threads(), n);
    assert!(std::ptr::eq(pool_of(true, None), pool(true)));
    assert!(std::ptr::eq(pool_of(false, None), pool(false)));
    assert_eq!(count(false, Some(n + 7)), n);
    for k in 2..n.min(5) {
      let p = pool_of(false, Some(k));
      assert_eq!(p.current_num_threads(), k);
      assert_eq!(p.install(rayon::current_num_threads), k);
      assert!(std::ptr::eq(p, pool_of(true, Some(k))), "kept");
    }
  }
}
