//! Benchmark of the `ecdsa-pop` plugin on an ETSI CD credential, per mode.
//!
//!   cargo run --release -p cd-ecdsa-pop [--features raw-mode,parallel] --bin ecdsa-pop-bench -- \
//!       [--n N] [--limb-bits 64|96|128] [--profile shared-bit|separate-pa] [--threads off|max|N] [--out PATH]
//!
//! Software device; timings are p50 in milliseconds.  "offline" is the
//! request-independent preparation (commitments, transfer sets, on-curve
//! proof; in raw mode also the 128 SM rounds).  "online" starts when the
//! request arrives: ETSI ProofGen (independent of the device), the device
//! signature, and the plugin work after the signature.
use std::cell::RefCell;
use std::time::Instant;

use bbs_cd_plugin::envelope::{prepare_credential, present, PresentStats, Verifier, VerifyStats};
use bbs_cd_plugin::issuer::{AttrValue, Issuer};
use bbs_cd_plugin::par::Parallelism;
use bbs_cd_plugin::plugin::PluginProver;
use bbs_cd_plugin::request::{CredentialRequest, PluginRequest, Request};
use bbs_cd_plugin::schema::{AttributeSpec, Schema};
use cd_ecdsa_pop::attestation::{key_input, Manufacturer, P256KeyHandler};
use cd_ecdsa_pop::device::HashSigner;
use cd_ecdsa_pop::params::{PROFILE_SEPARATE_PA, PROFILE_SHARED_BIT};
use cd_ecdsa_pop::*;
use cd_tom256::config::{n_limbs, TransferConfig};
use rand_core::OsRng;
use serde_json::{json, Value};

fn p50(xs: &mut [f64]) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let k = (xs.len() - 1) as f64 * 0.5;
    let (lo, hi) = (k.floor() as usize, (k.floor() as usize + 1).min(xs.len() - 1));
    xs[lo] + (xs[hi] - xs[lo]) * (k - lo as f64)
}

fn ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

const ROWS: [(&str, &str); 8] = [
    ("offline preparation", "prepare"),
    ("online: ETSI ProofGen (independent of the device)", "bbs"),
    ("online: device signature (software)", "sign"),
    ("online: plugin work after the signature", "post_sign"),
    ("online total (sequential, no device latency)", "online"),
    ("verify: ETSI ProofVerify", "verify_bbs"),
    ("verify: plugin", "verify_plugin"),
    ("verify total", "verify"),
];

fn main() {
    let mut n = 20usize;
    let mut limb_bits = 96u8;
    let mut profile = PROFILE_SHARED_BIT.to_vec();
    let mut par = Parallelism::Off;
    let mut out_path: Option<String> = None;
    let mut it = std::env::args().skip(1);
    while let Some(x) = it.next() {
        match x.as_str() {
            "--n" => n = it.next().unwrap().parse().unwrap(),
            "--limb-bits" => limb_bits = it.next().unwrap().parse().unwrap(),
            "--profile" => {
                profile = match it.next().unwrap().as_str() {
                    "shared-bit" => PROFILE_SHARED_BIT.to_vec(),
                    "separate-pa" => PROFILE_SEPARATE_PA.to_vec(),
                    p => panic!("unknown profile {p}"),
                }
            }
            "--threads" => par = Parallelism::parse(&it.next().unwrap()).expect("off|max|N"),
            "--out" => out_path = Some(it.next().unwrap()),
            other => panic!("unknown argument {other}"),
        }
    }
    assert!(n >= 2);
    let man = Manufacturer::new();
    let verifier = Verifier::new().register(Box::new(EcdsaPopVerifier { parallelism: par, ..Default::default() }));
    let mut modes = vec![Mode::Hashed];
    if cfg!(feature = "raw-mode") {
        modes.push(Mode::Raw);
    }
    let mut results = serde_json::Map::new();
    let mut table: Vec<Vec<f64>> = vec![];
    for &mode in &modes {
        // A device key is attested for exactly one mode (H-2): one credential per mode.
        let schema = Schema::new(
            "bench",
            vec![
                AttributeSpec::scalars("device_key", mode.key_type(), n_limbs(limb_bits) as u16, limb_bits as u16),
                AttributeSpec::octets("name"),
                AttributeSpec::octets("birth_date"),
                AttributeSpec::octets("nationality"),
                AttributeSpec::octets("country"),
            ],
        )
        .unwrap();
        let iss = Issuer::new(schema, vec![Box::new(P256KeyHandler::new(vec![man.public_key()], mode))]).unwrap();
        let (dev, att) = man.provision(mode, false);
        let cred = iss
            .issue(&[
                AttrValue::Input(key_input(&dev.hash_public_key().unwrap(), &att)),
                AttrValue::Octets(b"Alice".to_vec()),
                AttrValue::Octets(b"1990-01-01".to_vec()),
                AttrValue::Octets(b"SE".to_vec()),
                AttrValue::Octets(b"DK".to_vec()),
            ])
            .unwrap();
        let issuers = [iss.params.clone()];
        let params = EcdsaParams { mode, profile: profile.clone(), transfer: TransferConfig::recommended(limb_bits) };
        let mk_req = || {
            Request::new(
                b"rp.example",
                vec![CredentialRequest::new(&iss.params, &["nationality"])],
                vec![PluginRequest {
                    plugin_id: PLUGIN_ID.to_vec(),
                    credential: 0,
                    attribute: "device_key".into(),
                    params: params.encode(),
                }],
                &mut OsRng,
            )
        };
        let mut series: std::collections::BTreeMap<&str, Vec<f64>> = Default::default();
        let mut bytes = 0usize;
        for i in 0..=n {
            if i > 0 {
                eprint!("\r{mode:?} round {i}/{n}");
            }
            let req = mk_req();
            let t = Instant::now();
            let cslot = prepare_credential(&cred, &["device_key"], &mut OsRng).unwrap();
            let input = cslot.committed_input(&cred, 0, "device_key").unwrap();
            let pslot = prepare(&input, &params, 4, par, &mut OsRng).unwrap();
            let t_prep = t.elapsed();
            let st = RefCell::new(ProveStats::default());
            let signer = match mode {
                Mode::Hashed => Signer::Hash(&dev),
                #[cfg(feature = "raw-mode")]
                Mode::Raw => Signer::Raw(&dev),
                #[cfg(not(feature = "raw-mode"))]
                Mode::Raw => unreachable!(),
            };
            let mut prover = EcdsaPopProver::new(pslot, signer);
            prover.parallelism = par;
            prover.stats = Some(&st);
            let mut ps = PresentStats::default();
            let out = present(
                &req,
                &[&cred],
                vec![cslot],
                vec![Box::new(prover) as Box<dyn PluginProver>],
                &mut OsRng,
                Some(&mut ps),
            )
            .unwrap();
            let mut vs = VerifyStats::default();
            verifier.verify(&issuers, &req, &out, None, Some(&mut vs)).unwrap();
            if i == 0 {
                continue; // warm-up (fixed-base tables)
            }
            let s = st.borrow();
            let online = ms(ps.total);
            for (k, v) in [
                ("prepare", ms(t_prep)),
                ("bbs", ms(ps.bbs)),
                ("sign", ms(s.device_sign)),
                ("post_sign", ms(s.post_sign)),
                ("online", online),
                ("verify_bbs", ms(vs.bbs)),
                ("verify_plugin", ms(vs.plugins[0])),
                ("verify", ms(vs.total)),
            ] {
                series.entry(k).or_default().push(v);
            }
            bytes = out.len();
        }
        eprintln!();
        let mut col = vec![];
        let mut obj = serde_json::Map::new();
        for (_, k) in ROWS {
            let v = p50(series.get_mut(k).unwrap());
            col.push(v);
            obj.insert(k.to_string(), json!(v));
        }
        obj.insert("bytes".into(), json!(bytes));
        col.push(bytes as f64);
        table.push(col);
        results.insert(format!("{mode:?}").to_lowercase(), Value::Object(obj));
    }
    println!(
        "ecdsa-pop: {} round(s), limb_bits {}, profile {}, parallelism {:?} ({} thread(s)); p50 ms",
        n,
        limb_bits,
        String::from_utf8_lossy(&profile),
        par,
        par.threads()
    );
    print!("{:<52}", "");
    for m in &modes {
        print!("{:>12}", format!("{m:?}"));
    }
    println!();
    for (r, (name, _)) in ROWS.iter().enumerate() {
        print!("{name:<52}");
        for col in &table {
            print!("{:>12.1}", col[r]);
        }
        println!();
    }
    print!("{:<52}", "presentation bytes");
    for col in &table {
        print!("{:>12}", col[ROWS.len()] as u64);
    }
    println!();
    let res = json!({
        "crate": format!("cd-ecdsa-pop {}", env!("CARGO_PKG_VERSION")),
        "env": {"os": std::env::consts::OS, "arch": std::env::consts::ARCH, "parallelism": format!("{par:?}"), "threads": par.threads(),
                "debug_assertions": cfg!(debug_assertions)},
        "n": n, "limb_bits": limb_bits, "profile": String::from_utf8_lossy(&profile), "units": "milliseconds (p50); bytes",
        "modes": Value::Object(results),
    });
    if let Some(p) = out_path {
        std::fs::write(&p, serde_json::to_string_pretty(&res).unwrap()).unwrap();
        eprintln!("wrote {p}");
    }
    if cfg!(debug_assertions) {
        eprintln!("WARNING: debug build; use --release");
    }
}
