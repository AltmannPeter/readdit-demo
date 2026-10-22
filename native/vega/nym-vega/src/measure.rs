//! Timing and memory of the heavy steps.
//!
//! Heap memory ([`Heap`]) is what this addon's own Rust code holds: the addon's counting allocator
//! wraps the system allocator, so a step's figure is the most it held above what was held when it
//! began. That is the step's own requirement, on every platform; Node, V8, the other addons and the
//! keys or circuits loaded at start are not in it.
//!
//! Peak memory ([`Peak`]) is the process's peak resident set size (VmHWM in `/proc/self/status`) during a
//! step, after resetting the peak with `5` in `/proc/self/clear_refs` (Linux 4.0 and later). The
//! process is the site's server, so the figure includes Node and both sides' keys. Elsewhere the
//! figure is unavailable and reported as absent. One heavy step runs at a time ([`exclusive`]),
//! so no other heavy step runs while a step is measured.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

/// Milliseconds since `start`.
pub fn ms(start: Instant) -> f64 {
  (start.elapsed().as_secs_f64() * 1e6).round() / 1e3
}

static HEAVY: Mutex<()> = Mutex::new(());

/// Runs heavy steps one at a time.
pub fn exclusive() -> Result<MutexGuard<'static, ()>, String> {
  HEAVY.lock().map_err(|_| "a previous step panicked while holding the step lock".to_string())
}

/// A peak-memory measurement in progress: None when the platform cannot reset the peak.
pub struct Peak(Option<()>);

impl Peak {
  /// Resets the process's peak RSS to its current RSS.
  pub fn start() -> Self {
    Peak(std::fs::write("/proc/self/clear_refs", "5").ok())
  }

  /// The peak RSS since [`Peak::start`], in MB (10^6 bytes).
  pub fn read(&self) -> Option<f64> {
    self.0?;
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    let kb: f64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some((kb * 1.024).round() / 1e3)
  }
}

/// The heap this addon's Rust code holds, and its high-water mark, as the addon's counting
/// allocator reports them (`node/src/alloc.rs`, the one place with the `unsafe` an allocator
/// needs). Without that allocator (the crate's own tests) nothing is counted and the figures are
/// absent.
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static HIGH: AtomicUsize = AtomicUsize::new(0);
static COUNTING: AtomicBool = AtomicBool::new(false);

/// The allocator handed out `n` more bytes.
pub fn heap_grew(n: usize) {
  COUNTING.store(true, Relaxed);
  let now = CURRENT.fetch_add(n, Relaxed) + n;
  HIGH.fetch_max(now, Relaxed);
}

/// The allocator took `n` bytes back.
pub fn heap_shrank(n: usize) {
  CURRENT.fetch_sub(n, Relaxed);
}

/// A heap measurement in progress: the bytes held when it began, and the high-water mark since.
/// One heavy step runs at a time ([`exclusive`]), so the mark is the step's.
pub struct Heap {
  base: usize,
}

impl Heap {
  /// Starts a measurement: the high-water mark is reset to what is held now.
  pub fn start() -> Self {
    let base = CURRENT.load(Relaxed);
    HIGH.store(base, Relaxed);
    Heap { base }
  }

  /// The bytes held when the measurement began.
  pub fn base(&self) -> usize {
    self.base
  }

  /// The most bytes held at once since [`Heap::start`].
  pub fn high(&self) -> usize {
    HIGH.load(Relaxed).max(self.base)
  }
}

/// Bytes as MB (10^6 bytes), to 0.1 MB; absent when the heap is not counted.
pub fn mb(bytes: usize) -> Option<f64> {
  COUNTING.load(Relaxed).then(|| (bytes as f64 / 1e5).round() / 10.0)
}
