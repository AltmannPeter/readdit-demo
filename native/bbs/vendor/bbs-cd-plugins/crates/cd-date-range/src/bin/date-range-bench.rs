//! Benchmark of the `date-range` plugin: the one-time table build, proof
//! time, verification time and proof size for three typical questions, and
//! one full presentation (BBS proof + plugin) for the 18+ question.
//!
//! ```text
//! cargo run --release -p cd-date-range --bin date-range-bench -- \
//!     [--n 30] [--out results/NAME.tsv] [--compare results/BASELINE.tsv]
//! ```
//!
//! Single thread; median (min) in ms over n runs after 2 warm-up runs.
//! `--out` writes a TSV that `--compare` reads back.
use std::collections::BTreeMap;
use std::time::Instant;

use bbs_cd_plugin::envelope::{prepare_credential, present, Verifier};
use bbs_cd_plugin::issuer::{AttrValue, Issuer};
use bbs_cd_plugin::plugin::{EnvContext, PluginProver, PluginVerifier};
use bbs_cd_plugin::request::{CredentialRequest, PluginRequest, Request};
use bbs_cd_plugin::schema::{AttributeSpec, Schema};
use cd_date_range::fixed::FixedBase;
use cd_date_range::{
    date_input, DateHandler, DateRangeParams, DateRangeProver, DateRangeVerifier, PLUGIN_ID, TYPE_DATE,
};
use rand_core::{OsRng, RngCore};

fn median_min(mut xs: Vec<f64>) -> (f64, f64) {
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = xs.len();
    let med = if n % 2 == 1 { xs[n / 2] } else { (xs[n / 2 - 1] + xs[n / 2]) / 2.0 };
    (med, xs[0])
}

fn time<F: FnMut()>(n: usize, mut f: F) -> (f64, f64) {
    for _ in 0..2 {
        f();
    }
    median_min(
        (0..n)
            .map(|_| {
                let t = Instant::now();
                f();
                t.elapsed().as_secs_f64() * 1e3
            })
            .collect(),
    )
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

fn main() -> bbs_cd_plugin::Result<()> {
    let mut n = 30usize;
    let mut out: Option<String> = None;
    let mut compare: Option<String> = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--n" => n = it.next().expect("--n N").parse().expect("--n N"),
            "--out" => out = Some(it.next().expect("--out PATH")),
            "--compare" => compare = Some(it.next().expect("--compare PATH")),
            s => panic!("unknown argument {s} (usage: [--n N] [--out PATH] [--compare PATH])"),
        }
    }
    assert!(n >= 1);
    if cfg!(debug_assertions) {
        eprintln!("WARNING: debug build; run with --release for meaningful numbers");
    }
    // (case, op, median, min) and proof sizes per case
    let mut res: Vec<(String, String, f64, f64)> = Vec::new();
    let mut sizes: BTreeMap<String, (usize, usize)> = BTreeMap::new();

    let schema = Schema::new(
        "date-bench",
        vec![AttributeSpec::octets("name"), AttributeSpec::scalars("birth_date", TYPE_DATE, 1, 17)],
    )?;
    let issuer = Issuer::new(schema, vec![Box::new(DateHandler)])?;
    let cred = issuer.issue(&[AttrValue::Octets(b"Alice".to_vec()), AttrValue::Input(date_input("1990-05-17"))])?;
    let (_, spec, _) = issuer.params.schema.find("birth_date").unwrap();
    let spec = spec.clone();

    // One-time cost per process: the Y0/Y1 tables (built on first use).
    let (y0, y1) = (cd_date_range::fixed::generators().y0.point(), cd_date_range::fixed::generators().y1.point());
    let tb = time(n.min(5), || {
        std::hint::black_box((FixedBase::new(&y0), FixedBase::new(&y1)));
    });
    res.push(("setup".into(), "build_tables_once".into(), tb.0, tb.1));
    sizes.insert("setup".into(), (0, 0));

    let cases = [
        ("le_18plus", DateRangeParams::le(20081018)),
        ("ge_under50", DateRangeParams::ge(19761019)),
        ("range_18_to_49", DateRangeParams::between(19761019, 20081018)),
    ];
    for (case, p) in cases {
        eprintln!("{case} ({p}) ...");
        let params = p.encode();
        let mut env = vec![0u8; 256];
        OsRng.fill_bytes(&mut env);
        let ectx = EnvContext { nonce: env[..32].to_vec(), ctx: vec![], env, plugin_index: 0 };
        let slot = prepare_credential(&cred, &["birth_date"], &mut OsRng)?;
        let input = slot.committed_input(&cred, 0, "birth_date")?;
        let view = input.view();
        let mut proof = vec![];
        let tp = time(n, || {
            proof = Box::new(DateRangeProver::new()).prove(&ectx, &input, &params, &mut OsRng).unwrap();
        });
        let tv = time(n, || {
            DateRangeVerifier.verify(&ectx, &view, &params, &proof, &mut OsRng).unwrap();
        });
        assert_eq!(proof.len(), cd_date_range::proof_len(&spec, &params)?);
        res.push((case.into(), "prove".into(), tp.0, tp.1));
        res.push((case.into(), "verify".into(), tv.0, tv.1));
        sizes.insert(case.into(), ((proof.len() - 36) / 144, proof.len()));
    }

    // One full presentation: BBS proof with the date committed + plugin.
    let case = "presentation_18plus";
    eprintln!("{case} ...");
    let req = Request::new(
        b"rp.example",
        vec![CredentialRequest::new(&issuer.params, &["name"])],
        vec![PluginRequest {
            plugin_id: PLUGIN_ID.to_vec(),
            credential: 0,
            attribute: "birth_date".into(),
            params: DateRangeParams::le(20081018).encode(),
        }],
        &mut OsRng,
    );
    let verifier = Verifier::new().register(Box::new(DateRangeVerifier));
    let mut pres = vec![];
    let tp = time(n, || {
        let slot = prepare_credential(&cred, &["birth_date"], &mut OsRng).unwrap();
        pres = present(
            &req,
            &[&cred],
            vec![slot],
            vec![Box::new(DateRangeProver::new()) as Box<dyn PluginProver>],
            &mut OsRng,
            None,
        )
        .unwrap();
    });
    let tv = time(n, || {
        verifier.verify(std::slice::from_ref(&issuer.params), &req, &pres, None, None).unwrap();
    });
    res.push((case.into(), "commit_and_present".into(), tp.0, tp.1));
    res.push((case.into(), "verify".into(), tv.0, tv.1));
    sizes.insert(case.into(), (0, pres.len()));

    // ---------------------------------------------------- report
    let base = compare.as_deref().map(read_tsv);
    println!("date-range benchmark: n = {n} (+2 warm-up), single thread; median (min) in ms");
    let mut last = String::new();
    for (case, op, med, min) in &res {
        if *case != last {
            let (k, b) = sizes[case];
            let what = match (k, b) {
                (0, 0) => "one-time, per process".to_string(),
                (0, b) => format!("{b} bytes"),
                (k, b) => format!("{k} bit proofs, proof {b} bytes"),
            };
            println!("\n[{case}]  {what}");
            last = case.clone();
        }
        let delta = base
            .as_ref()
            .and_then(|b| b.get(&(case.clone(), op.clone())))
            .map(|(bm, _)| format!("   was {bm:>8.3}  {:+7.1}%", (med - bm) / bm * 100.0))
            .unwrap_or_default();
        println!("  {op:<20}{med:>9.3} ({min:>8.3}){delta}");
    }
    if let Some(path) = out {
        let mut t = String::from("# date-range benchmark (date-range-bench)\ncase\top\tmedian_ms\tmin_ms\n");
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
    Ok(())
}
