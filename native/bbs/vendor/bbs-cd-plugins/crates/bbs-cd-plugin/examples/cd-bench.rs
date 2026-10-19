//! Benchmark of the BBS committed-disclosure core (`bbs_cd`) alone: no
//! plugin, no envelope, no device binding.  Only public `bbs_cd` entry points
//! are timed, so the same benchmark runs unchanged before and after
//! optimizations of the core.
//!
//! ```text
//! cargo run --release -p bbs-cd-plugin --example cd-bench -- \
//!     [--n 20] [--shapes 10:6:1,40:6:10,128:6:60] [--suite sha256|shake256] \
//!     [--out results/NAME.tsv] [--compare results/BASELINE.tsv]
//! ```
//!
//! A shape `L:C:D` is a credential of L messages, of which the first C are
//! SCALAR messages that are committed (like the device-key limbs) and the
//! next D are OCTETS messages that are disclosed; the rest are hidden OCTETS.
//! `10:6:1` is the shape `ecdsa-pop` uses with 96-bit limbs.
//!
//! Every operation is timed separately: warm-up runs first, then `n` timed
//! runs; the median and the minimum are reported in milliseconds.  The core
//! is single-threaded.  `--out` writes a TSV that `--compare` reads back.
#![allow(non_snake_case)]

use std::collections::BTreeMap;
use std::time::Instant;

use bbs_cd::helpers::in_g1;
use bbs_cd::interface::{KeyGen, PrecomputeCommitment, ProofGen, ProofVerify, Sign, SkToPk, Verify};
use bbs_cd::params::Ciphersuite;
use bbs_cd::primitives::{decode_G1, octets_to_pubkey, point_to_octets_E1};
use bbs_cd::types::{DisclosureState, Index, Message, MessageType, COMMIT, DISCLOSE, HIDE, OCTETS, SCALAR};
use bbs_cd::utils::{calculate_domain, create_generators, octets_to_proof};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, Scalar};
use rand_core::{OsRng, RngCore};

const WARMUP: usize = 2;

fn median_min(mut xs: Vec<f64>) -> (f64, f64) {
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = xs.len();
    let med = if n % 2 == 1 { xs[n / 2] } else { (xs[n / 2 - 1] + xs[n / 2]) / 2.0 };
    (med, xs[0])
}

/// Time `f` (warm-up + n runs); returns (median, min) in ms.
fn time<F: FnMut()>(n: usize, mut f: F) -> (f64, f64) {
    for _ in 0..WARMUP {
        f();
    }
    let xs = (0..n)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_secs_f64() * 1e3
        })
        .collect();
    median_min(xs)
}

fn rand_scalar() -> Scalar {
    let mut b = [0u8; 64];
    OsRng.fill_bytes(&mut b);
    Scalar::from_bytes_wide(&b)
}

struct Shape {
    l: usize,
    c: usize,
    d: usize,
}

fn parse_shapes(s: &str) -> Vec<Shape> {
    s.split(',')
        .map(|t| {
            let v: Vec<usize> = t.split(':').map(|x| x.trim().parse().expect("shape L:C:D")).collect();
            assert!(v.len() == 3 && v[1] + v[2] <= v[0] && v[0] >= 1, "bad shape {t}");
            Shape { l: v[0], c: v[1], d: v[2] }
        })
        .collect()
}

/// (case, op) -> (median, min), for `--compare`.
type Baseline = BTreeMap<(String, String), (f64, f64)>;

fn read_tsv(path: &str) -> Baseline {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let mut r = Baseline::new();
    for line in text.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() >= 4 && f[0] != "case" {
            r.insert((f[0].into(), f[1].into()), (f[2].parse().unwrap(), f[3].parse().unwrap()));
        }
    }
    r
}

fn main() {
    let mut n = 20usize;
    let mut shapes = parse_shapes("10:6:1,40:6:10,128:6:60");
    let mut suite = Ciphersuite::Sha256;
    let mut out: Option<String> = None;
    let mut compare: Option<String> = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--n" => n = it.next().expect("--n N").parse().expect("--n N"),
            "--shapes" => shapes = parse_shapes(&it.next().expect("--shapes L:C:D,...")),
            "--suite" => {
                suite = match it.next().expect("--suite").as_str() {
                    "sha256" => Ciphersuite::Sha256,
                    "shake256" => Ciphersuite::Shake256,
                    s => panic!("unknown suite {s}"),
                }
            }
            "--out" => out = Some(it.next().expect("--out PATH")),
            "--compare" => compare = Some(it.next().expect("--compare PATH")),
            "-h" | "--help" => {
                println!("see the module documentation at the top of crates/bbs-cd-plugin/examples/cd-bench.rs");
                return;
            }
            s => panic!("unknown argument {s}"),
        }
    }
    assert!(n >= 1);
    if cfg!(debug_assertions) {
        eprintln!("WARNING: debug build; run with --release for meaningful numbers");
    }
    let api = suite.api_id();
    // (case, op, median, min), in measurement order
    let mut res: Vec<(String, String, f64, f64)> = Vec::new();
    let mut bytes: BTreeMap<String, usize> = BTreeMap::new();

    // ---------------------------------------------------- primitives
    // Library costs; they do not change with core optimizations and serve to
    // compare machines and to attribute the end-to-end numbers.
    let mut put = |case: &str, op: &str, v: (f64, f64)| {
        res.push((case.to_string(), op.to_string(), v.0, v.1));
    };
    let p = G1Projective::generator() * rand_scalar();
    let s = rand_scalar();
    let enc = point_to_octets_E1(&p);
    let sk = KeyGen(suite, &[7u8; 32], b"cd-bench", None).unwrap();
    let pk = SkToPk(sk).unwrap();
    let w = G2Affine::from(octets_to_pubkey(&pk).unwrap());
    let pa = G1Affine::from(p);
    let pm = 10 * n;
    put(
        "primitives",
        "g1_scalar_mul",
        time(pm, || {
            std::hint::black_box(p * s);
        }),
    );
    put(
        "primitives",
        "in_g1_one_point",
        time(pm, || {
            std::hint::black_box(in_g1(&[p]));
        }),
    );
    put(
        "primitives",
        "decode_g1",
        time(pm, || {
            std::hint::black_box(decode_G1(&enc, false).unwrap());
        }),
    );
    put(
        "primitives",
        "decode_pubkey_g2",
        time(pm, || {
            std::hint::black_box(octets_to_pubkey(&pk).unwrap());
        }),
    );
    put(
        "primitives",
        "two_pairings",
        time(n, || {
            std::hint::black_box(pairing(&pa, &w) + pairing(&pa, &G2Affine::generator()));
        }),
    );

    // ---------------------------------------------------- end to end
    let header = [0x48u8; 64];
    let ph = [0x50u8; 64];
    for sh in &shapes {
        let case = format!("L{}_C{}_D{}", sh.l, sh.c, sh.d);
        eprintln!("{case} ...");
        let mut msgs = Vec::with_capacity(sh.l);
        let mut types: Vec<MessageType> = Vec::with_capacity(sh.l);
        let mut states: Vec<DisclosureState> = Vec::with_capacity(sh.l);
        for i in 0..sh.l {
            if i < sh.c {
                // a 96-bit limb, like the device-key attribute
                let mut b = [0u8; 32];
                OsRng.fill_bytes(&mut b[20..]);
                msgs.push(Message::Scalar(bbs_cd::types::ScalarInput(b)));
                types.push(SCALAR);
                states.push(COMMIT);
            } else {
                msgs.push(Message::Octets(format!("attribute-{i:03}-value").into_bytes()));
                types.push(OCTETS);
                states.push(if i < sh.c + sh.d { DISCLOSE } else { HIDE });
            }
        }
        let idx: Vec<Index> = (0..sh.c).map(|i| Index::Integer(i as u64)).collect();
        let disclosed: Vec<Message> = msgs[sh.c..sh.c + sh.d].to_vec();

        let mut sig = vec![];
        put(&case, "sign", time(n, || sig = Sign(suite, sk, &pk, &header, &msgs, &types).unwrap()));
        put(&case, "verify_signature", time(n, || Verify(suite, &pk, &sig, &header, &msgs, &types).unwrap()));
        let gens = create_generators(suite, sh.l as u128 + 1, &api).unwrap();
        put(
            &case,
            "calculate_domain",
            time(n, || {
                std::hint::black_box(calculate_domain(suite, &pk, &gens[0], &gens[1..], &header, &api).unwrap());
            }),
        );
        let mut pre = (vec![], vec![]);
        put(
            &case,
            "precompute_commitment",
            time(n, || pre = PrecomputeCommitment(suite, &msgs[..sh.c], &idx, &types, None).unwrap()),
        );
        let (commitments, rands) = pre;
        let mut proof = vec![];
        put(
            &case,
            "proof_gen",
            time(n, || {
                proof = ProofGen(suite, &pk, &sig, &header, &ph, &msgs, &types, &states, Some(&rands), None).unwrap().0
            }),
        );
        put(
            &case,
            "decode_proof",
            time(n, || {
                std::hint::black_box(octets_to_proof(&proof).unwrap());
            }),
        );
        put(
            &case,
            "proof_verify",
            time(n, || {
                ProofVerify(suite, &pk, &proof, &header, &ph, &disclosed, &commitments, &types, &states).unwrap()
            }),
        );
        bytes.insert(case.clone(), proof.len());
    }

    // ---------------------------------------------------- report
    let base = compare.as_deref().map(read_tsv);
    println!(
        "bbs_cd core benchmark: suite {:?}, n = {n} (+{WARMUP} warm-up), single thread; median (min) in ms",
        suite
    );
    let mut last_case = String::new();
    for (case, op, med, min) in &res {
        if *case != last_case {
            println!("\n[{case}]{}", bytes.get(case).map(|b| format!("  proof {b} bytes")).unwrap_or_default());
            last_case = case.clone();
        }
        let delta = base
            .as_ref()
            .and_then(|b| b.get(&(case.clone(), op.clone())))
            .map(|(bm, _)| format!("   was {bm:>9.3}  {:+7.1}%", (med - bm) / bm * 100.0))
            .unwrap_or_default();
        println!("  {op:<24}{med:>10.3} ({min:>8.3}){delta}");
    }
    if let Some(path) = out {
        let mut t = String::from("# bbs_cd core benchmark (cd-bench)\ncase\top\tmedian_ms\tmin_ms\n");
        for (case, op, med, min) in &res {
            t.push_str(&format!("{case}\t{op}\t{med:.4}\t{min:.4}\n"));
        }
        if let Some(dir) = std::path::Path::new(&path).parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).expect("create output directory");
            }
        }
        std::fs::write(&path, t).unwrap_or_else(|e| panic!("write {path}: {e}"));
        eprintln!("wrote {path}");
    }
}
