//! Before and after P1 and P2: times and memory of the two prover phases, over N runs on the
//! rulebook's test vector (redirect session, age 13–17).
//!
//!   cargo run --release --example compare --features aes-rng -- variant=after rng=aes runs=25 threads=1
//!
//! - `variant=before`: the unmodified v0.6 crate (`nym-auth-zk-decoy`); `after`: this crate (P1).
//! - `rng=os`: Google's `SecureRandomEngine` (one OS call per draw); `aes`: `AesCtrRng` (P2, needs
//!   `--features aes-rng`). A fresh engine per proof either way.
//! - `threads=N`: the proving pool's size (default 1).
//! - `warmup=N` unmeasured runs first (default 2).
//!
//! Run each configuration as its own process: the peak resident set is the process's.
//!
//! Reports medians, minimum and maximum of:
//! - prebuild time (phase 1, before the device signature) and after-PIN time (`prove_prebuilt`);
//! - heap (a counting allocator: what this process's Rust code allocated, above what it held when
//!   the phase began): the peak during prebuild, what the prebuilt state holds into phase 2, and
//!   the peak during phase 2;
//! - the hash circuit's Ligero table (after only);
//! - the process's peak resident set at the end (getrusage; Linux and macOS).
//!
//! Every presentation is verified (outside the timings) by the crate that made it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Instant;

use runtime_random::{RandomEngine, SecureRandomEngine};
use serde_json::Value;

struct Counting;
static CUR: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to the system allocator unchanged; only counts the bytes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            let now = CUR.fetch_add(l.size(), Relaxed) + l.size();
            PEAK.fetch_max(now, Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        CUR.fetch_sub(l.size(), Relaxed);
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            let now = CUR.fetch_add(l.size(), Relaxed) + l.size();
            PEAK.fetch_max(now, Relaxed);
        }
        p
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        let q = System.realloc(p, l, n);
        if !q.is_null() {
            if n >= l.size() {
                let now = CUR.fetch_add(n - l.size(), Relaxed) + n - l.size();
                PEAK.fetch_max(now, Relaxed);
            } else {
                CUR.fetch_sub(l.size() - n, Relaxed);
            }
        }
        q
    }
}

#[global_allocator]
static A: Counting = Counting;

/// Starts a phase: the peak restarts at what is held now, which is returned.
fn phase() -> usize {
    let now = CUR.load(Relaxed);
    PEAK.store(now, Relaxed);
    now
}

fn peak_rss_bytes() -> u64 {
    // SAFETY: getrusage writes the struct it is given; zeroed is a valid rusage.
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) } != 0 {
        return 0;
    }
    let m = u64::try_from(u.ru_maxrss).unwrap_or(0);
    if cfg!(target_os = "macos") { m } else { m * 1024 }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

#[derive(Default)]
struct Sample {
    prebuild_ms: f64,
    after_ms: f64,
    pre_peak: usize,
    held: usize,
    after_peak: usize,
    table: usize,
}

enum Rng {
    Os,
    #[cfg(feature = "aes-rng")]
    Aes,
}

fn engine(r: &Rng) -> Box<dyn FnMut(usize) -> Vec<u8>> {
    match r {
        Rng::Os => {
            let mut e = SecureRandomEngine::new();
            Box::new(move |n| e.bytes(n))
        }
        #[cfg(feature = "aes-rng")]
        Rng::Aes => {
            let mut e = nym_auth_zk_decoy_opt::AesCtrRng::new();
            Box::new(move |n| e.bytes(n))
        }
    }
}

/// The engine behind a boxed closure, so one code path serves both engines.
struct Dyn(Box<dyn FnMut(usize) -> Vec<u8>>);
impl RandomEngine for Dyn {
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (self.0)(len)
    }
}

/// One crate's runs: `$k` is the crate, `$table` reads the prebuilt table's size.
macro_rules! runs {
    ($k:ident, $v:expr, $rng:expr, $n:expr, $warm:expr, $table:expr) => {{
        use $k::{AgeRange, Holder, Prover, Request, Session, Verifier};
        let v: &Value = $v;
        let s = |p: &[&str]| p.iter().fold(v, |x, k| &x[*k]).as_str().unwrap().to_string();
        let i = &v["sessions"]["redirect"]["inputs"];
        let r = Request {
            issuer_key: (hex(&s(&["keys", "document_signer", "x"])).try_into().unwrap(), hex(&s(&["keys", "document_signer", "y"])).try_into().unwrap()),
            proof_time: s(&["expected", "age_check", "proof_time"]),
            age_range: Some(AgeRange::parse("13-17").unwrap()),
            verifier_id: s(&["expected", "pseudonym_inputs", "verifier_id"]),
            session: Session::Redirect {
                client_id: i["client_id"].as_str().unwrap().into(),
                nonce: i["nonce"].as_str().unwrap().into(),
                jwk_thumbprint: i["jwk_thumbprint"].as_str().map(|t| hex(t).try_into().unwrap()),
                response_uri: i["response_uri"].as_str().unwrap().into(),
            },
        };
        let cred = hex(&s(&["issuer_signed_cbor"]));
        let holder = Holder {
            credential: &cred,
            secret_seed: hex(&s(&["holder_openings", "secret_seed"])).try_into().unwrap(),
            birth_date: s(&["holder_openings", "birth_date"]).as_bytes().try_into().unwrap(),
        };
        let sig: [u8; 64] = hex(&s(&["sessions", "redirect", "device_signature_r_s"])).try_into().unwrap();
        let prover = Prover::load().unwrap();
        let verifier = Verifier::load().unwrap();
        let mut out = Vec::new();
        let mut failed = 0;
        for k in 0..$warm + $n {
            let mut rng = Dyn(engine($rng));
            let base = phase();
            let t = Instant::now();
            let pre = prover.prebuild(&r, &holder, &mut rng).unwrap();
            let prebuild_ms = t.elapsed().as_secs_f64() * 1e3;
            let pre_peak = PEAK.load(Relaxed) - base;
            let held = CUR.load(Relaxed).saturating_sub(base);
            let table = $table(&pre);
            let mid = phase();
            let t = Instant::now();
            let p = prover.prove_prebuilt(pre, &sig, &mut rng).unwrap();
            let after_ms = t.elapsed().as_secs_f64() * 1e3;
            let after_peak = PEAK.load(Relaxed) - mid + held;
            drop(rng);
            if verifier.verify(&r, &p).is_err() {
                failed += 1;
            }
            if k >= $warm {
                out.push(Sample { prebuild_ms, after_ms, pre_peak, held, after_peak, table });
            }
        }
        (out, failed)
    }};
}

fn stats<T: Copy + PartialOrd>(mut x: Vec<T>) -> (T, T, T) {
    x.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (x[x.len() / 2], x[0], x[x.len() - 1])
}

fn main() {
    let mut variant = "after".to_string();
    let mut rng = "os".to_string();
    let (mut runs, mut threads, mut warm) = (25usize, 1usize, 2usize);
    for a in std::env::args().skip(1) {
        let (k, v) = a.split_once('=').unwrap_or_else(|| panic!("{a}: name=value"));
        match k {
            "variant" => variant = v.into(),
            "rng" => rng = v.into(),
            "runs" => runs = v.parse().unwrap(),
            "threads" => threads = v.parse().unwrap(),
            "warmup" => warm = v.parse().unwrap(),
            _ => panic!("unknown option {k}"),
        }
    }
    let r = match rng.as_str() {
        "os" => Rng::Os,
        #[cfg(feature = "aes-rng")]
        "aes" => Rng::Aes,
        _ => panic!("rng={rng}: os, or aes with --features aes-rng"),
    };
    let p = format!("{}/tests/data/decoy_test_vectors.json", env!("CARGO_MANIFEST_DIR"));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
    let (samples, failed) = pool.install(|| match variant.as_str() {
        "before" => runs!(nym_auth_zk_decoy, &v, &r, runs, warm, |_: &nym_auth_zk_decoy::Prebuilt| 0usize),
        "after" => runs!(nym_auth_zk_decoy_opt, &v, &r, runs, warm, |p: &nym_auth_zk_decoy_opt::Prebuilt| p.table_bytes()),
        _ => panic!("variant={variant}: before or after"),
    });
    let rss = peak_rss_bytes();
    let ms = |f: fn(&Sample) -> f64| stats(samples.iter().map(f).collect());
    let mb = |f: fn(&Sample) -> usize| {
        let (a, b, c) = stats(samples.iter().map(f).collect());
        (a as f64 / 1e6, b as f64 / 1e6, c as f64 / 1e6)
    };
    let (pb, at) = (ms(|s| s.prebuild_ms), ms(|s| s.after_ms));
    let (pp, held, ap, tb) = (mb(|s| s.pre_peak), mb(|s| s.held), mb(|s| s.after_peak), mb(|s| s.table));
    let aes_hw = if cfg!(target_arch = "aarch64") { if cfg!(aes_armv8) { " (AES: ARMv8)" } else { " (AES: software; build with --cfg aes_armv8)" } } else { "" };
    println!("{variant} rng={rng}{aes_hw} threads={threads} runs={runs} (+{warm} warm-up) verified={}/{}", runs + warm - failed, runs + warm);
    println!("  prebuild ms      median {:8.2}  min {:8.2}  max {:8.2}", pb.0, pb.1, pb.2);
    println!("  after-PIN ms     median {:8.2}  min {:8.2}  max {:8.2}", at.0, at.1, at.2);
    println!("  total ms         median {:8.2}", ms(|s| s.prebuild_ms + s.after_ms).0);
    println!("  heap MB: prebuild peak {:.2}, held into phase 2 {:.2}, phase 2 peak {:.2}", pp.0, held.0, ap.0);
    if variant == "after" {
        println!("  hash Ligero table MB {:.3}", tb.0);
    }
    println!("  peak RSS MB {:.1}", rss as f64 / 1e6);
    println!(
        "JSON {}",
        serde_json::json!({
            "variant": variant, "rng": rng, "threads": threads, "runs": runs, "failed": failed,
            "prebuild_ms": [pb.0, pb.1, pb.2], "after_ms": [at.0, at.1, at.2],
            "heap_mb": { "prebuild_peak": pp.0, "held": held.0, "after_peak": ap.0, "table": tb.0 },
            "peak_rss_mb": rss as f64 / 1e6,
            "arch": std::env::consts::ARCH, "os": std::env::consts::OS,
        })
    );
    assert_eq!(failed, 0, "a presentation did not verify");
}
