//! Timing and peak memory of the heavy steps.
//!
//! Peak memory is the process's peak resident set size (VmHWM in `/proc/self/status`) during a
//! step, after resetting the peak with `5` in `/proc/self/clear_refs` (Linux 4.0 and later). The
//! process is the site's server, so the figure includes Node and both sides' keys. Elsewhere the
//! figure is unavailable and reported as absent. One heavy step runs at a time ([`exclusive`]),
//! so a step's peak and time are its own.

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
