//! Full-flow benchmark: one presentation with the ETSI BBS committed-disclosure
//! proof, `ecdsa-pop` (hashed mode, software device), `date-range` (18+ by
//! default) and `pseudonym` (configuration `known-offender-matching-ssc`), on
//! one credential.  Times each part on the holder and the verifier.
//!
//! ```text
//! cargo run --release -p cd-date-range --example full-flow-bench -- \
//!     [--n 20] [--limb-bits 64|96|128] [--threads off|max|N] \
//!     [--le YYYYMMDD] [--ge YYYYMMDD] [--out results/NAME.tsv] [--compare results/BASELINE.tsv]
//! ```
//!
//! `--threads` needs the `parallel` feature of the ecdsa-pop crate:
//! `--features cd-ecdsa-pop/parallel` (only `ecdsa-pop` uses threads).
//!
//! Each round uses a fresh request.  "offline" is the request-independent
//! holder work (BBS commitments and the ecdsa-pop preparation); "online"
//! starts when the request arrives.  Round 0 is a warm-up.  Median (min) in
//! ms over n rounds.  `--out` writes a TSV that `--compare` reads back.
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use bbs_cd_plugin::envelope::{parse, prepare_credential, present, PresentStats, Verifier, VerifyStats};
use bbs_cd_plugin::issuer::{AttrValue, Issuer};
use bbs_cd_plugin::par::Parallelism;
use bbs_cd_plugin::plugin::PluginProver;
use bbs_cd_plugin::request::{CredentialRequest, PluginRequest, Request};
use bbs_cd_plugin::schema::{AttributeSpec, Schema};
use cd_date_range::{
    date_input, DateHandler, DateRangeParams, DateRangeProver, DateRangeVerifier, Ymd, RECOMMENDED_BITS, TYPE_DATE,
};
use cd_ecdsa_pop::attestation::{key_input, Manufacturer, P256KeyHandler};
use cd_ecdsa_pop::{
    prepare, EcdsaParams, EcdsaPopProver, EcdsaPopVerifier, HashSigner, Mode, ProveStats, Signer, TYPE_P256_KEY_HASHED,
};
use cd_pseudonym::{
    new_seed, NymSeedHandler, PseudonymParams, PseudonymProver, PseudonymVerifier, TYPE_NYM_SEED_ISSUER_KNOWN,
};
use cd_tom256::config::n_limbs;
use rand_core::OsRng;

/// (key, label), in report order.
const ROWS: [(&str, &str); 16] = [
    ("setup_tables", "setup: date-range generator tables (once per process)"),
    ("holder_offline", "holder offline: BBS commitments + ecdsa-pop preparation"),
    ("holder_bbs", "holder online: ETSI ProofGen"),
    ("holder_ecdsa_pop", "holder online: ecdsa-pop (incl. device signature)"),
    ("holder_device_sign", "  of which: device signature (software)"),
    ("holder_date_range", "holder online: date-range"),
    ("holder_pseudonym", "holder online: pseudonym"),
    ("holder_online", "holder online total"),
    ("holder_total", "holder total (offline + online)"),
    ("verify_parse", "verify: parse"),
    ("verify_bbs", "verify: ETSI ProofVerify"),
    ("verify_ecdsa_pop", "verify: ecdsa-pop"),
    ("verify_date_range", "verify: date-range"),
    ("verify_pseudonym", "verify: pseudonym"),
    ("verify_total", "verify total"),
    ("end_to_end", "holder total + verify total"),
];

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn median_min(xs: &mut [f64]) -> (f64, f64) {
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = xs.len();
    let med = if n % 2 == 1 { xs[n / 2] } else { (xs[n / 2 - 1] + xs[n / 2]) / 2.0 };
    (med, xs[0])
}

fn read_tsv(path: &str) -> BTreeMap<String, f64> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.len() >= 4 && f[0] != "case").then(|| (f[1].to_string(), f[2].parse().unwrap()))
        })
        .collect()
}

fn date_arg(s: Option<String>) -> u32 {
    let n: u32 = s.expect("date YYYYMMDD").parse().expect("date YYYYMMDD");
    Ymd::from_yyyymmdd(n).expect("valid YYYYMMDD");
    n
}

fn main() -> bbs_cd_plugin::Result<()> {
    let mut n = 20usize;
    let mut limb_bits = 96u8;
    let mut par = Parallelism::Off;
    let (mut ge, mut le): (Option<u32>, Option<u32>) = (None, None);
    let mut out: Option<String> = None;
    let mut compare: Option<String> = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--n" => n = it.next().expect("--n N").parse().expect("--n N"),
            "--limb-bits" => limb_bits = it.next().expect("--limb-bits B").parse().expect("64|96|128"),
            "--threads" => par = Parallelism::parse(&it.next().expect("--threads")).expect("off|max|N"),
            "--le" => le = Some(date_arg(it.next())),
            "--ge" => ge = Some(date_arg(it.next())),
            "--out" => out = Some(it.next().expect("--out PATH")),
            "--compare" => compare = Some(it.next().expect("--compare PATH")),
            s => panic!("unknown argument {s}; see the header of examples/full-flow-bench.rs"),
        }
    }
    assert!(n >= 1);
    if cfg!(debug_assertions) {
        eprintln!("WARNING: debug build; run with --release for meaningful numbers");
    }
    let age = match (ge, le) {
        (None, None) => DateRangeParams::le(20081018),
        (g, l) => DateRangeParams {
            ge: g.map(|x| Ymd::from_yyyymmdd(x).unwrap()),
            le: l.map(|x| Ymd::from_yyyymmdd(x).unwrap()),
        },
    };

    // Setup, once per process: the date-range tables (an app would do this
    // at start or when a request arrives).
    let t = Instant::now();
    cd_date_range::precompute();
    let setup_tables = ms(t.elapsed());

    // Issuer, device and credential: device key (hashed ECDSA), name,
    // birth date, pseudonym seed, nationality.
    let schema = Schema::new(
        "pid-bench",
        vec![
            AttributeSpec::scalars("device_key", TYPE_P256_KEY_HASHED, n_limbs(limb_bits) as u16, limb_bits as u16),
            AttributeSpec::octets("name"),
            AttributeSpec::scalars("birth_date", TYPE_DATE, 1, RECOMMENDED_BITS),
            AttributeSpec::scalars("nym_seed", TYPE_NYM_SEED_ISSUER_KNOWN, 1, 255),
            AttributeSpec::octets("nationality"),
        ],
    )?;
    let man = Manufacturer::new();
    let issuer = Issuer::new(
        schema,
        vec![
            Box::new(P256KeyHandler::new(vec![man.public_key()], Mode::Hashed)),
            Box::new(DateHandler),
            Box::new(NymSeedHandler),
        ],
    )?;
    let (dev, att) = man.provision(Mode::Hashed, false);
    let cred = issuer.issue(&[
        AttrValue::Input(key_input(&dev.hash_public_key()?, &att)),
        AttrValue::Octets(b"Alice".to_vec()),
        AttrValue::Input(date_input("1990-05-17")),
        AttrValue::Input(new_seed(&mut OsRng).to_vec()),
        AttrValue::Octets(b"SE".to_vec()),
    ])?;
    let issuers = [issuer.params.clone()];
    let ecdsa = EcdsaParams::hashed(limb_bits);
    // The relying party's identifier, as the wallet reads it from the access
    // certificate.
    let rp: &[u8] = b"https://rp.example";
    let nym = PseudonymParams::known_offender_matching(rp);
    let verifier = Verifier::new()
        .register(Box::new(EcdsaPopVerifier { parallelism: par, ..EcdsaPopVerifier::new() }))
        .register(Box::new(DateRangeVerifier))
        .register(Box::new(PseudonymVerifier::for_verifier(rp)));

    let mut series: BTreeMap<&str, Vec<f64>> = BTreeMap::new();
    // presentation, BBS proof, ecdsa-pop, date-range, pseudonym
    let mut sizes = (0usize, 0usize, 0usize, 0usize, 0usize);
    for round in 0..=n {
        if round > 0 {
            eprint!("\rround {round}/{n}");
        }
        let req = Request::new(
            b"rp.example",
            vec![CredentialRequest::new(&issuer.params, &["nationality"])],
            vec![
                PluginRequest {
                    plugin_id: cd_ecdsa_pop::PLUGIN_ID.to_vec(),
                    credential: 0,
                    attribute: "device_key".into(),
                    params: ecdsa.encode(),
                },
                PluginRequest {
                    plugin_id: cd_date_range::PLUGIN_ID.to_vec(),
                    credential: 0,
                    attribute: "birth_date".into(),
                    params: age.encode(),
                },
                PluginRequest {
                    plugin_id: cd_pseudonym::PLUGIN_ID.to_vec(),
                    credential: 0,
                    attribute: "nym_seed".into(),
                    params: nym.encode(),
                },
            ],
            &mut OsRng,
        );

        // Holder, offline.
        let t = Instant::now();
        let slot = prepare_credential(&cred, &["device_key", "birth_date", "nym_seed"], &mut OsRng)?;
        let key = slot.committed_input(&cred, 0, "device_key")?;
        let pop_slot = prepare(&key, &ecdsa, 4, par, &mut OsRng)?;
        let offline = ms(t.elapsed());

        // Holder, online.
        let st = RefCell::new(ProveStats::default());
        let mut pop = EcdsaPopProver::new(pop_slot, Signer::Hash(&dev));
        pop.parallelism = par;
        pop.stats = Some(&st);
        let provers: Vec<Box<dyn PluginProver>> =
            vec![Box::new(pop), Box::new(DateRangeProver::new()), Box::new(PseudonymProver::new(rp))];
        let mut ps = PresentStats::default();
        let pres = present(&req, &[&cred], vec![slot], provers, &mut OsRng, Some(&mut ps))?;

        // Verifier.
        let mut vs = VerifyStats::default();
        let verified = verifier.verify(&issuers, &req, &pres, None, Some(&mut vs))?;
        assert_eq!(verified.outputs[1], age.encode());
        if round == 0 {
            let pe = parse(&pres, &issuers, &req)?;
            let len = |r: (usize, usize)| r.1 - r.0;
            sizes = (
                pres.len(),
                len(pe.credentials[0].bbs_range),
                len(pe.plugin_ranges[0]),
                len(pe.plugin_ranges[1]),
                len(pe.plugin_ranges[2]),
            );
            continue; // warm-up
        }
        let online = ms(ps.total);
        for (k, v) in [
            ("holder_offline", offline),
            ("holder_bbs", ms(ps.bbs)),
            ("holder_ecdsa_pop", ms(ps.plugins[0])),
            ("holder_device_sign", ms(st.borrow().device_sign)),
            ("holder_date_range", ms(ps.plugins[1])),
            ("holder_pseudonym", ms(ps.plugins[2])),
            ("holder_online", online),
            ("holder_total", offline + online),
            ("verify_parse", ms(vs.parse)),
            ("verify_bbs", ms(vs.bbs)),
            ("verify_ecdsa_pop", ms(vs.plugins[0])),
            ("verify_date_range", ms(vs.plugins[1])),
            ("verify_pseudonym", ms(vs.plugins[2])),
            ("verify_total", ms(vs.total)),
            ("end_to_end", offline + online + ms(vs.total)),
        ] {
            series.entry(k).or_default().push(v);
        }
    }
    eprintln!();

    // ---------------------------------------------------- report
    let base = compare.as_deref().map(read_tsv);
    println!(
        "full flow: BBS CD proof + ecdsa-pop (hashed, {limb_bits}-bit limbs) + date-range ({age}) \
         + pseudonym ({}); n = {n}, ecdsa-pop threads: {}; median (min) in ms",
        nym.config,
        par.threads()
    );
    let mut rows: Vec<(&str, f64, f64)> = vec![("setup_tables", setup_tables, setup_tables)];
    for (k, _) in &ROWS[1..] {
        let (med, min) = median_min(series.get_mut(k).unwrap());
        rows.push((k, med, min));
    }
    for ((k, label), (_, med, min)) in ROWS.iter().zip(&rows) {
        let delta = base
            .as_ref()
            .and_then(|b| b.get(*k))
            .map(|bm| format!("   was {bm:>8.2}  {:+6.1}%", (med - bm) / bm * 100.0))
            .unwrap_or_default();
        println!("  {label:<58}{med:>9.2} ({min:>8.2}){delta}");
    }
    let (total, bbs, pop, dr, ps) = sizes;
    println!("  presentation {total} bytes: BBS proof {bbs}, ecdsa-pop {pop}, date-range {dr}, pseudonym {ps}");
    if let Some(path) = out {
        let mut t = String::from("# full-flow benchmark (full-flow-bench)\ncase\top\tmedian_ms\tmin_ms\n");
        for (k, med, min) in &rows {
            t.push_str(&format!("full_flow\t{k}\t{med:.4}\t{min:.4}\n"));
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
