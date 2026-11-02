//! The sampling profiler behind `/tech`'s Profiling switch: which functions a proof or a check
//! spends its time in.
//!
//! [`Sampler::start`] starts pprof's sampler (a SIGPROF timer and a stack walk per sample; that
//! code is pprof's, this crate has no `unsafe`), and [`Sampler::finish`] turns the samples into
//! folded stacks: each sample's frames from the step's entry point down to the function that was
//! running, as `entry;…;leaf`, with the number of samples that had that stack. A sample counts when
//! one of its frames belongs to the addon's own code (`roots`); the frames above the outermost such
//! frame (Node, libuv, the napi glue) are cut off, and so are the frames of the thread pool's and
//! the panic guard's plumbing. Samples without such a frame (Node's own threads, an idle worker)
//! are counted apart, as `other`, and samples whose stack could not be walked, as `lost`.
//!
//! Every profile also counts the samples per thread (`threads`, by the thread's name: the addons'
//! pools name theirs, such as `longfellow-4-2`). [`Mode::Full`] (`"profile": "full"` in a step's
//! JSON) adds `full`: every sample's whole stack, nothing cut, the thread's name as its first
//! frame, `other` and `lost` samples included. It is for exports (`npm run bench profiling=full`),
//! not for /tech's flame graphs.
//!
//! The sampler is process-wide: one runs at a time. The site calls one profiled step at a time
//! (`server/utils/services.ts`), so the samples are that step's. A sampler that cannot start (one
//! is already running) gives no profile; the step itself is unaffected.

use std::collections::BTreeMap;
use std::time::Instant;

use serde_json::{Value as Json, json};

/// Samples per second the sampler asks for. The kernel's timer may deliver fewer (Linux: at most
/// one per scheduler tick); the profile reports the samples it got.
pub const HZ: i32 = 997;

/// Code the sampler does not walk a stack from: the unwinder itself, the dynamic loader and the
/// vDSO. The C library is walked: memcpy, memset and malloc take real time in a proof (copying and
/// zeroing large vectors), and a sampler that skipped them would hand their time to the rest.
/// glibc's loader lock, the one lock a stack walk takes, is recursive, so a walk from inside the C
/// library cannot deadlock its own thread.
const BLOCKLIST: &[&str] = &["libgcc", "vdso", "ld-linux", "ld-musl", "libunwind", "dyld"];

/// What a step asked for: no profile, /tech's profile, or that and every stack in full.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Mode {
  #[default]
  Off,
  On,
  Full,
}

impl Mode {
  /// The mode a step's JSON input asks for in `profile`: `true`, `"full"`, or anything else (or
  /// input that is not JSON) for off.
  pub fn of(input: &str) -> Self {
    let v = serde_json::from_str::<Json>(input).ok();
    match v.as_ref().and_then(|v| v.get("profile")) {
      Some(Json::Bool(true)) => Mode::On,
      Some(Json::String(s)) if s == "full" => Mode::Full,
      _ => Mode::Off,
    }
  }

  pub fn on(self) -> bool {
    self != Mode::Off
  }
}

/// A sampler in progress, or none (profiling off, or another one running).
pub struct Sampler {
  guard: Option<pprof::ProfilerGuard<'static>>,
  started: Instant,
  roots: &'static [&'static str],
  full: bool,
}

impl Sampler {
  /// Starts sampling unless `mode` is off. `roots`: the path prefixes of the addon's own code
  /// (`["nym_vega::", "vega_age::", …]`).
  pub fn start(mode: Mode, roots: &'static [&'static str]) -> Self {
    let guard = mode.on().then(|| pprof::ProfilerGuardBuilder::default().frequency(HZ).blocklist(BLOCKLIST).build().ok()).flatten();
    Sampler { guard, started: Instant::now(), roots, full: mode == Mode::Full }
  }

  /// Stops sampling: the folded stacks (`stacks`), the samples kept (`samples`), the samples of
  /// other threads (`other`) and those whose stack could not be walked (`lost`), every sample by
  /// thread (`threads`), the wall time sampled in ms (`ms`) and the requested rate (`hz`); in
  /// [`Mode::Full`], also `full`. None when the sampler did not run.
  pub fn finish(self) -> Option<Json> {
    let guard = self.guard?;
    let ms = (self.started.elapsed().as_secs_f64() * 1e6).round() / 1e3;
    let report = guard.report().build().ok()?;
    drop(guard);
    let mut stacks: BTreeMap<String, u64> = BTreeMap::new();
    let mut threads: BTreeMap<String, u64> = BTreeMap::new();
    let mut full: BTreeMap<String, u64> = BTreeMap::new();
    let (mut kept, mut other, mut lost) = (0u64, 0u64, 0u64);
    for (frames, &count) in report.data.iter() {
      let count = count.max(0) as u64;
      // pprof lists a sample's frames from the leaf up; each frame may hold inlined functions,
      // innermost first.
      let names: Vec<String> = frames.frames.iter().flat_map(|f| f.iter().map(|s| clean(&s.name()))).collect();
      let thread = clean(&frames.thread_name_or_id());
      *threads.entry(thread.clone()).or_default() += count;
      if self.full {
        let whole: Vec<&str> = std::iter::once(thread.as_str()).chain(names.iter().rev().map(|n| if n.is_empty() { "Unknown" } else { n.as_str() })).collect();
        *full.entry(whole.join(";")).or_default() += count;
      }
      // A stack the unwinder could not walk past its first frame (code without unwind tables).
      if names.iter().all(|n| n.is_empty() || n == "Unknown") {
        lost += count;
        continue;
      }
      let Some(top) = names.iter().rposition(|n| self.roots.iter().any(|r| n.starts_with(r))) else {
        other += count;
        continue;
      };
      let path: Vec<&str> = names[..=top].iter().rev().map(String::as_str).filter(|n| !plumbing(n)).collect();
      if path.is_empty() {
        other += count;
        continue;
      }
      *stacks.entry(path.join(";")).or_default() += count;
      kept += count;
    }
    let mut out = json!({ "hz": HZ, "ms": ms, "samples": kept, "other": other, "lost": lost, "threads": threads, "stacks": stacks });
    if self.full {
      out["full"] = json!(full);
    }
    Some(out)
  }
}

/// Frames that only carry the work to where it runs: the thread pool's scheduling, closures'
/// call shims, the panic guard, the stack walk itself.
fn plumbing(name: &str) -> bool {
  const PREFIXES: &[&str] = &[
    "rayon_core::",
    "rayon::",
    "core::ops::function::",
    "std::panicking::",
    "std::panic::",
    "core::panic::",
    "__rust_try",
    "std::sys::backtrace::",
    "backtrace::",
    "pprof::",
    "alloc::boxed::",
  ];
  // A closure's call shim (`…::{closure}::call_once`): the closure itself is the next frame.
  let shim = ["}::call_once", "}::call_mut", "}::call"].iter().any(|e| name.ends_with(e));
  // rayon's iterator plumbing implemented for a type of the caller's (`usize::drive_unindexed`).
  const RAYON: &[&str] = &["::drive_unindexed", "::with_producer", "::fold_with", "::consume_iter", "::bridge_producer_consumer", "::callback"];
  shim || PREFIXES.iter().any(|p| name.starts_with(p)) || RAYON.iter().any(|e| name.ends_with(e))
}

/// A demangled name, shortened: no hash, no generic arguments, and `<T as Trait>::f` as `T::f`.
pub fn clean(name: &str) -> String {
  let name = match name.rfind("::h") {
    Some(i) if name.len() - i == 19 && name[i + 3..].bytes().all(|b| b.is_ascii_hexdigit()) => &name[..i],
    _ => name,
  };
  let b = name.as_bytes();
  let mut out = String::with_capacity(name.len());
  let mut i = 0;
  while i < b.len() {
    match b[i] {
      b'<' => {
        let close = matching(b, i);
        let inner = &name[i + 1..close];
        // A qualified path at the start, `<T as Trait>` or `<T>`: keep T, cleaned.
        if i == 0 {
          let t = top_level_as(inner).map_or(inner, |k| &inner[..k]);
          out.push_str(&clean(t));
        }
        // Otherwise generic arguments (`f<T>`, `f::<T>`): dropped.
        i = close + 1;
      }
      c => {
        out.push(c as char);
        i += 1;
      }
    }
  }
  let out = out.replace("::::", "::");
  let out = out.trim_end_matches("::");
  let out = ["&mut ", "&", "*mut ", "*const ", "dyn "].iter().fold(out, |o, p| o.strip_prefix(p).unwrap_or(o));
  // `;` separates frames in a folded stack.
  closures(&out.replace("{{closure}}", "{closure}")).replace(';', ",")
}

/// `{closure#0}` (v0 mangling) as `{closure}`.
fn closures(s: &str) -> String {
  let mut out = String::with_capacity(s.len());
  let mut rest = s;
  while let Some(i) = rest.find("{closure#") {
    out.push_str(&rest[..i]);
    out.push_str("{closure}");
    rest = rest[i..].find('}').map_or("", |j| &rest[i + j + 1..]);
  }
  out.push_str(rest);
  out
}

/// The index of the `>` that closes the `<` at `open` (the end when unbalanced).
fn matching(b: &[u8], open: usize) -> usize {
  let mut depth = 0usize;
  for (j, &c) in b.iter().enumerate().skip(open) {
    match c {
      b'<' => depth += 1,
      b'>' if j > 0 && b[j - 1] == b'-' => {} // `->` in a fn type
      b'>' => {
        depth -= 1;
        if depth == 0 {
          return j;
        }
      }
      _ => {}
    }
  }
  b.len().saturating_sub(1)
}

/// The position of ` as ` at the top nesting level of `s`.
fn top_level_as(s: &str) -> Option<usize> {
  let b = s.as_bytes();
  let mut depth = 0i32;
  for (j, &c) in b.iter().enumerate() {
    match c {
      b'<' => depth += 1,
      b'>' => depth -= 1,
      b' ' if depth == 0 && s[j..].starts_with(" as ") => return Some(j),
      _ => {}
    }
  }
  None
}

#[cfg(test)]
mod tests {
  use super::clean;

  #[test]
  fn names() {
    assert_eq!(clean("vega_prover::sumcheck::SumcheckProof<E>::prove_quad::h0123456789abcdef"), "vega_prover::sumcheck::SumcheckProof::prove_quad");
    assert_eq!(clean("<vega_prover::provider::msm::Foo<G> as core::ops::Fn<(A,)>>::call"), "vega_prover::provider::msm::Foo::call");
    assert_eq!(clean("nym_vega::prover::Prover::prove::{{closure}}"), "nym_vega::prover::Prover::prove::{closure}");
    assert_eq!(clean("<alloc::vec::Vec<T> as core::iter::FromIterator<T>>::from_iter"), "alloc::vec::Vec::from_iter");
    assert_eq!(clean("a::b::{closure#0}::{closure#12}"), "a::b::{closure}::{closure}");
    assert_eq!(clean("core::iter::adapters::map::map_fold::<usize, F, (), <X>::low_bits::{closure#0}>::{closure#0}"), "core::iter::adapters::map::map_fold::{closure}");
    assert_eq!(clean("<&halo2curves::t256::fp::Fp as core::ops::Mul>::mul"), "halo2curves::t256::fp::Fp::mul");
    assert_eq!(clean("<[F; 4] as x::Y>::z"), "[F, 4]::z");
  }
}

#[cfg(test)]
mod sampling {
  #[inline(never)]
  fn burn(n: u64) -> u64 {
    let mut x = 0u64;
    for i in 0..n {
      x = x.wrapping_mul(6364136223846793005).wrapping_add(i);
    }
    x
  }

  #[test]
  fn samples_a_busy_loop_and_full_keeps_every_frame() {
    let s = super::Sampler::start(super::Mode::On, &["nym_profile::"]);
    let x = std::hint::black_box(burn(std::hint::black_box(600_000_000)));
    let p = s.finish().expect("a profile");
    eprintln!("{x} {}", serde_json::to_string_pretty(&p).unwrap());
    assert!(p["samples"].as_u64().unwrap() > 10);
    assert!(p.get("full").is_none());
    let total: u64 = p["threads"].as_object().unwrap().values().map(|v| v.as_u64().unwrap()).sum();
    assert_eq!(total, p["samples"].as_u64().unwrap() + p["other"].as_u64().unwrap() + p["lost"].as_u64().unwrap());

    // Full, in the same test: the sampler is process-wide, and tests run side by side.
    let s = super::Sampler::start(super::Mode::Full, &["nym_profile::"]);
    let x = std::hint::black_box(burn(std::hint::black_box(600_000_000)));
    let p = s.finish().expect("a profile");
    eprintln!("{x}");
    let full = p["full"].as_object().unwrap();
    let total: u64 = full.values().map(|v| v.as_u64().unwrap()).sum();
    assert_eq!(total, p["threads"].as_object().unwrap().values().map(|v| v.as_u64().unwrap()).sum::<u64>());
    // The test harness's own frames sit above the test function: nothing is cut.
    assert!(full.keys().any(|k| k.contains("nym_profile::sampling::burn") && k.contains("test::")), "{full:?}");
  }

  #[test]
  fn modes() {
    use super::Mode;
    assert_eq!(Mode::of(r#"{"profile":true}"#), Mode::On);
    assert_eq!(Mode::of(r#"{"profile":"full"}"#), Mode::Full);
    assert_eq!(Mode::of(r#"{"profile":false}"#), Mode::Off);
    assert_eq!(Mode::of(r#"{"profile":"yes"}"#), Mode::Off);
    assert_eq!(Mode::of("not json"), Mode::Off);
  }
}
