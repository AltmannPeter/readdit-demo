//! Compares builds of this crate: the default (threaded), `--no-default-features`, and
//! `--features reference` (Google's ZkProver and ZkVerifier themselves). TEST ONLY: it proves
//! with a deterministic random engine, which a wallet must never use.
//!
//!   cargo run --release --example gates -- prove  <dir>   # writes <dir>/<case>.bin, prints digests
//!   cargo run --release --example gates -- verify <dir>   # prints a verdict per check
//!
//! Two builds give the same proof bytes when `prove` prints the same lines, and the same
//! verdicts when `verify` (over the same proofs) prints the same lines. Each line names the
//! thread count separately (`threads …`), so a diff that ignores that line compares the rest.

use nym_auth_zk::{AgeRange, Holder, Presentation, Prover, Request, Session, Verifier};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use runtime_random::DeterministicRng;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn hex(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    let s = if s.len() % 2 == 1 { format!("0{s}") } else { s.to_string() };
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}
fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex(s).try_into().unwrap()
}
fn enc(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn json(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{}/tests/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap()
}

/// One presentation to make: its request, the holder's credential and secrets, the device
/// signature.
struct Case {
    name: String,
    request: Request,
    credential: Vec<u8>,
    seed: [u8; 16],
    birth: [u8; 10],
    signature: [u8; 64],
}

fn vector_case(file: &str, session: &str, range: Option<&str>) -> Case {
    let v = json(&format!("data/{file}"));
    let s = |p: &[&str]| p.iter().fold(&v, |x, k| &x[*k]).as_str().unwrap().to_string();
    let i = &v["sessions"][session]["inputs"];
    let t = i["jwk_thumbprint"].as_str().map(arr::<32>);
    let sess = match session {
        "redirect" => Session::Redirect {
            client_id: i["client_id"].as_str().unwrap().into(),
            nonce: i["nonce"].as_str().unwrap().into(),
            jwk_thumbprint: t,
            response_uri: i["response_uri"].as_str().unwrap().into(),
        },
        _ => Session::DcApi { origin: i["origin"].as_str().unwrap().into(), nonce: i["nonce"].as_str().unwrap().into(), jwk_thumbprint: t },
    };
    Case {
        name: format!("vector-{}-{session}-{}", file.trim_end_matches(".json").trim_start_matches("nym_auth_test_vectors"), range.unwrap_or("none")),
        request: Request {
            issuer_key: (arr(&s(&["keys", "document_signer", "x"])), arr(&s(&["keys", "document_signer", "y"]))),
            proof_time: s(&["expected", "age_check", "proof_time"]),
            age_range: range.map(|r| AgeRange::parse(r).unwrap()),
            verifier_id: s(&["expected", "pseudonym_inputs", "verifier_id"]),
            session: sess,
        },
        credential: hex(&s(&["issuer_signed_cbor"])),
        seed: arr(&s(&["holder_openings", "secret_seed"])),
        birth: s(&["holder_openings", "birth_date"]).as_bytes().try_into().unwrap(),
        signature: arr(&s(&["sessions", session, "device_signature_r_s"])),
    }
}

fn synthetic_case(holder: &str, proof_time: &str, range: Option<&str>) -> Case {
    let v = json("data/nym_auth_test_vectors.json");
    let k = &v["keys"]["document_signer"];
    let d = json(&format!("data/synthetic/holder{holder}.json"));
    let request = Request {
        issuer_key: (hex(k["x"].as_str().unwrap()).try_into().unwrap(), hex(k["y"].as_str().unwrap()).try_into().unwrap()),
        proof_time: proof_time.into(),
        age_range: range.map(|r| AgeRange::parse(r).unwrap()),
        verifier_id: "x509_san_dns:verifier.example".into(),
        session: Session::Redirect {
            client_id: "x509_san_dns:verifier.example".into(),
            nonce: "synthetic-nonce".into(),
            jwk_thumbprint: None,
            response_uri: "https://verifier.example/response".into(),
        },
    };
    let mut dk = [0u8; 32];
    let key = hex(d["device_d"].as_str().unwrap());
    dk[32 - key.len()..].copy_from_slice(&key);
    let sig: Signature = SigningKey::from_bytes(&dk.into()).unwrap().sign(&Prover::device_signed_bytes(&request));
    Case {
        name: format!("synthetic-{holder}-{}", range.unwrap_or("none")),
        request,
        credential: hex(d["issuer_signed"].as_str().unwrap()),
        seed: hex(d["secret_seed"].as_str().unwrap()).try_into().unwrap(),
        birth: d["birth_date"].as_str().unwrap().as_bytes().try_into().unwrap(),
        signature: sig.to_bytes().into(),
    }
}

fn cases() -> Vec<Case> {
    vec![
        vector_case("nym_auth_test_vectors.json", "redirect", Some("13-17")),
        vector_case("nym_auth_test_vectors.json", "dcapi", None),
        vector_case("nym_auth_test_vectors_zero_psc.json", "redirect", Some("16-")),
        vector_case("nym_auth_test_vectors_zero_psc.json", "dcapi", Some("13-17")),
        synthetic_case("B", "2026-10-28T09:00:00Z", Some("18+")),
        synthetic_case("C", "2026-10-28T09:00:00Z", Some("13-17")),
        synthetic_case("D", "2026-10-28T09:00:00Z", Some("18+")),
        synthetic_case("D", "2026-10-28T09:00:00Z", None),
    ]
}

fn prove(dir: &str) {
    std::fs::create_dir_all(dir).unwrap();
    let prover = Prover::load().unwrap();
    println!("threads {}", nym_auth_zk::threads());
    for (k, c) in cases().iter().enumerate() {
        let holder = Holder { credential: &c.credential, secret_seed: c.seed, birth_date: c.birth };
        // The same seed for both ways, so that they must give the same bytes too.
        let seed = 0x5eed_0000 + k as u64;
        let one = prover.prove(&c.request, &holder, &c.signature, &mut DeterministicRng::new(seed)).unwrap();
        let mut rng = DeterministicRng::new(seed);
        let pre = prover.prebuild(&c.request, &holder, &mut rng).unwrap();
        let two = prover.prove_prebuilt(pre, &c.signature, &mut rng).unwrap();
        for (way, p) in [("prove", &one), ("two-phase", &two)] {
            println!("{} {way} {} bytes sha256 {} nym {}", c.name, p.proof.len(), enc(&Sha256::digest(&p.proof)), enc(&p.pseudonym));
        }
        std::fs::write(format!("{dir}/{}.bin", c.name), [&one.pseudonym[..], &one.proof].concat()).unwrap();
    }
}

/// Every check on one presentation: it verifies, and each change is refused.
fn checks(verifier: &Verifier, name: &str, r: &Request, p: &Presentation, flips: usize) {
    let say = |what: &str, got: Result<(), nym_auth_zk::Error>| println!("{name} {what}: {got:?}");
    say("as made", verifier.verify(r, p));
    let n = p.proof.len();
    for k in 0..flips {
        // Spread over the proof, at positions that differ from run to run of k.
        let at = (k * n) / flips + (k * 7919) % (n / flips).max(1);
        let mut q = p.clone();
        q.proof[at] ^= 1 << (k % 8);
        say(&format!("flip {at}"), verifier.verify(r, &q));
    }
    let mut q = p.clone();
    q.proof.pop();
    say("truncated by one byte", verifier.verify(r, &q));
    let mut q = p.clone();
    q.proof.push(0);
    say("extended by one byte", verifier.verify(r, &q));
    let mut q = p.clone();
    q.pseudonym[3] ^= 1;
    say("another pseudonym", verifier.verify(r, &q));
    let mut o = r.clone();
    match &mut o.session {
        Session::Redirect { nonce, .. } | Session::DcApi { nonce, .. } => nonce.push('x'),
    }
    say("another nonce", verifier.verify(&o, p));
    let mut o = r.clone();
    o.age_range = Some(AgeRange::parse("0+").unwrap());
    say("another range", verifier.verify(&o, p));
    let mut o = r.clone();
    o.proof_time = "2026-10-27T12:00:01Z".into();
    say("another proof_time", verifier.verify(&o, p));
    let mut o = r.clone();
    o.issuer_key.0[31] ^= 1;
    say("another issuer key", verifier.verify(&o, p));
}

fn verify(dir: &str) {
    let verifier = Verifier::load().unwrap();
    println!("threads {}", nym_auth_zk::threads());
    for (k, c) in cases().iter().enumerate() {
        let b = std::fs::read(format!("{dir}/{}.bin", c.name)).unwrap();
        let p = Presentation { pseudonym: b[..32].try_into().unwrap(), proof: b[32..].to_vec() };
        checks(&verifier, &c.name, &c.request, &p, if k == 0 { 200 } else { 25 });
    }
    let gdir = format!("{}/tests/golden", env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<_> = std::fs::read_dir(&gdir).unwrap().map(|e| e.unwrap().path()).collect();
    files.sort();
    for path in files {
        let g: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let (r, p) = golden(&g);
        checks(&verifier, &format!("golden-{}", path.file_stem().unwrap().to_string_lossy()), &r, &p, 25);
    }
}

fn golden(g: &Value) -> (Request, Presentation) {
    let r = &g["request"];
    let st = |v: &Value| v.as_str().unwrap().to_string();
    let se = &r["session"];
    let t = se["jwk_thumbprint"].as_str().map(arr::<32>);
    let session = match se["type"].as_str().unwrap() {
        "redirect" => Session::Redirect { client_id: st(&se["client_id"]), nonce: st(&se["nonce"]), jwk_thumbprint: t, response_uri: st(&se["response_uri"]) },
        _ => Session::DcApi { origin: st(&se["origin"]), nonce: st(&se["nonce"]), jwk_thumbprint: t },
    };
    let request = Request {
        issuer_key: (arr(&st(&r["issuer_key"]["x"])), arr(&st(&r["issuer_key"]["y"]))),
        proof_time: st(&r["proof_time"]),
        age_range: r["age_range"].as_str().map(|a| AgeRange::parse(a).unwrap()),
        verifier_id: st(&r["verifier_id"]),
        session,
    };
    let p = &g["presentation"];
    (request, Presentation { pseudonym: arr(&st(&p["pseudonym"])), proof: hex(&st(&p["proof"])) })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match (args.get(1).map(String::as_str), args.get(2)) {
        (Some("prove"), Some(dir)) => prove(dir),
        (Some("verify"), Some(dir)) => verify(dir),
        _ => eprintln!("usage: gates prove|verify <dir>"),
    }
}
