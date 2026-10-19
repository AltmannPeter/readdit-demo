//! Optional parallelism (optimization A6).
//!
//! Two switches:
//! - the cargo feature `parallel` compiles in `rayon`; without it every
//!   setting runs sequentially and the binary has no thread pool;
//! - the runtime setting [`Parallelism`] chooses `Off` (sequential, the
//!   default), `Max` (all available cores) or `Threads(n)`.
//!
//! **Same output for every setting.**  Work items that need prover
//! randomness get their own ChaCha20 stream, seeded one after another from
//! the caller's RNG before any parallel work starts (`child_rngs`), and the
//! verifier draws all batch weights before parallel work starts.  Results
//! are collected in input order.  A fixed seed therefore gives a
//! byte-identical presentation, and the same verification result, for
//! `Off`, `Max` and any `Threads(n)`.
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

/// Runtime parallelism setting.  Ignored (treated as `Off`) unless the crate
/// is built with the `parallel` feature.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Parallelism {
    /// Sequential (the default).
    #[default]
    Off,
    /// One worker per available core.
    Max,
    /// Exactly `n` workers (`Threads(0)` and `Threads(1)` mean sequential).
    Threads(usize),
}

impl Parallelism {
    /// Number of workers actually used: always 1 without the `parallel`
    /// feature; otherwise capped at `MAX_THREADS` (one pool per distinct
    /// count is kept for the life of the process).
    pub fn threads(self) -> usize {
        if !cfg!(feature = "parallel") {
            return 1;
        }
        let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        match self {
            Parallelism::Off => 1,
            Parallelism::Threads(n) => n.clamp(1, MAX_THREADS),
            Parallelism::Max => cores.clamp(1, MAX_THREADS),
        }
    }

    /// Parse `off`, `max` or a thread count (`1` = off).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "off" | "0" | "1" => Some(Parallelism::Off),
            "max" => Some(Parallelism::Max),
            n => n.parse::<usize>().ok().map(Parallelism::Threads),
        }
    }
}

/// Upper bound on worker threads per pool.
pub const MAX_THREADS: usize = 64;

/// `n` independent ChaCha20 streams, seeded sequentially from `rng`.
pub fn child_rngs<R: RngCore + CryptoRng + ?Sized>(rng: &mut R, n: usize) -> Vec<ChaCha20Rng> {
    (0..n)
        .map(|_| {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            ChaCha20Rng::from_seed(seed)
        })
        .collect()
}

/// Order-preserving map over `items` on `par.threads()` workers.
pub fn map<T, U, F>(par: Parallelism, items: Vec<T>, f: F) -> Vec<U>
where
    T: Send,
    U: Send,
    F: Fn(T) -> U + Sync + Send,
{
    let n = par.threads();
    if n <= 1 || items.len() <= 1 {
        return items.into_iter().map(f).collect();
    }
    run_parallel(n, items, f)
}

/// Split `0..len` into at most `par.threads()` contiguous chunks (in order).
pub fn chunks(par: Parallelism, len: usize) -> Vec<std::ops::Range<usize>> {
    let k = par.threads().clamp(1, len.max(1));
    let size = len.div_ceil(k).max(1);
    (0..len).step_by(size).map(|a| a..(a + size).min(len)).collect()
}

#[cfg(feature = "parallel")]
fn run_parallel<T, U, F>(n: usize, items: Vec<T>, f: F) -> Vec<U>
where
    T: Send,
    U: Send,
    F: Fn(T) -> U + Sync + Send,
{
    use rayon::prelude::*;
    match pool(n) {
        Some(p) => p.install(|| items.into_par_iter().map(f).collect()),
        // the pool could not be built (e.g. thread limit): run sequentially
        None => items.into_iter().map(f).collect(),
    }
}

#[cfg(not(feature = "parallel"))]
fn run_parallel<T, U, F>(_n: usize, items: Vec<T>, f: F) -> Vec<U>
where
    T: Send,
    U: Send,
    F: Fn(T) -> U + Sync + Send,
{
    items.into_iter().map(f).collect()
}

/// One cached pool per thread count (pools are not rebuilt per call).
#[cfg(feature = "parallel")]
fn pool(n: usize) -> Option<std::sync::Arc<rayon::ThreadPool>> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    static POOLS: OnceLock<Mutex<HashMap<usize, Arc<rayon::ThreadPool>>>> = OnceLock::new();
    let mut m = POOLS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap_or_else(|e| e.into_inner());
    if let Some(p) = m.get(&n) {
        return Some(p.clone());
    }
    let p = Arc::new(
        rayon::ThreadPoolBuilder::new().num_threads(n).thread_name(|i| format!("devbind-par-{i}")).build().ok()?,
    );
    m.insert(n, p.clone());
    Some(p)
}
