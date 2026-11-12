//! The rulebook v0.5 core ([`vega_age::bsc`]) on the rulebook's test vectors (`tests/data`, both
//! credential variants, both sessions), on synthetic holders and on the fixture issuer:
//!
//! - every rule holds for the honest presentations, and each failing age case breaks exactly an
//!   age rule ([`app::first_broken`], which builds the rules with their values);
//! - the native witness ([`app::witness`]) equals, value for value, what the circuits' own gadgets
//!   compute, the core and every step instance;
//! - an honest proof is accepted with the vectors' pseudonym, and refused for other public values
//!   or a changed byte;
//! - the red-team cases: each dishonest witness or presentation breaks the rule named;
//! - the circuits as data are fixed: the v0.5 shapes, and the v0.4 shapes unchanged.

use std::sync::Arc;

use bellpepper_core::{ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};
use serde_json::Value as Json;
use vega_age::app;
use vega_age::bsc::{
  BSC_MDOC, BscCore, BscPresentation, BscPublic, BscWitness, DOC_TYPE, ITEM, NYM, OPENING, opening,
};
use vega_age::fixtures::KeyPair;
use vega_age::fixtures::cbor::{Item, Value, text};
use vega_age::fixtures::mdoc::issue_bsc;
use vega_age::gadgets::p256::{PublicKey, Signature};
use vega_age::presentation::{Date, Time};
use vega_age::pseudonym;
use vega_age::request::Pattern;
use vega_age::table::{Region, Table, sha256};
use vega_prover::provider::pt256::t256;
use vega_prover::traits::circuit::VegaCircuit;

fn unhex(s: &str) -> Vec<u8> {
  let s = s.trim_start_matches("0x");
  let s = if s.len() % 2 == 1 { format!("0{s}") } else { s.to_string() };
  (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
  let v = unhex(s);
  let mut out = [0u8; N];
  out[N - v.len()..].copy_from_slice(&v);
  out
}

fn json(name: &str) -> Json {
  let path = format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
  serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn date(s: &str) -> Date {
  Date {
    year: s[0..4].parse().unwrap(),
    month: s[5..7].parse().unwrap(),
    day: s[8..10].parse().unwrap(),
  }
}

fn time(s: &str) -> Time {
  let (h, m, sec) =
    (s[11..13].parse().unwrap(), s[14..16].parse().unwrap(), s[17..19].parse().unwrap());
  Time { date: date(s), hour: h, minute: m, second: sec }
}

/// What a credential gives the core: the Sig_structure, the bsc item, the issuer's (r, s).
struct Credential {
  sig_structure: Vec<u8>,
  item: Vec<u8>,
  issuer_signature: Signature,
}

/// Takes an IssuerSigned apart: the COSE_Sign1's Sig_structure and signature, the bsc item.
fn parse(issuer_signed: &[u8]) -> Credential {
  let root = Item::read(issuer_signed).unwrap();
  let auth = root.get(&text("issuerAuth")).unwrap();
  let protected = auth.at(0).unwrap().content().to_vec();
  let payload = auth.at(2).unwrap().content().to_vec();
  let sig = auth.at(3).unwrap().content();
  let sig_structure = Value::Array(vec![
    text("Signature1"),
    Value::Bytes(protected),
    Value::Bytes(vec![]),
    Value::Bytes(payload),
  ])
  .encode();
  let items = root.get(&text("nameSpaces")).unwrap().get(&text(DOC_TYPE)).unwrap();
  let item = items
    .children()
    .into_iter()
    .find(|i| i.embedded().unwrap().get(&text("elementIdentifier")).unwrap().content() == b"bsc")
    .unwrap()
    .bytes
    .to_vec();
  let issuer_signature =
    Signature::from_rs(&sig[..32].try_into().unwrap(), &sig[32..].try_into().unwrap());
  Credential { sig_structure, item, issuer_signature }
}

/// One presentation's inputs.
#[derive(Clone)]
struct Case {
  witness: BscWitness,
  public: BscPublic,
  device_signature: Signature,
}

impl Case {
  fn core(&self) -> BscCore {
    BscCore {
      witness: Some(Arc::new(self.witness.clone())),
      presentation: Some(BscPresentation {
        public: self.public.clone(),
        device_signature: self.device_signature,
      }),
    }
  }

  fn broken(&self) -> Option<String> {
    app::first_broken(&self.core()).unwrap()
  }

  /// The table rebuilt from its blocks, its chains recomputed (a prover's own table).
  fn rechained(&mut self, blocks: Vec<[u8; 64]>, start: [u8; 32]) {
    self.witness.table = Arc::new(Table::from_blocks_in(BSC_MDOC, blocks, start));
  }
}

/// The vectors' holder, `session` "redirect" or "dcapi", for the bounds E and C at proof_time.
fn vector_case(v: &Json, session: &str, born_from: Option<&str>, born_by: Option<&str>) -> Case {
  let s = |p: &[&str]| p.iter().fold(v, |x, k| &x[*k]).as_str().unwrap().to_string();
  let cred = parse(&unhex(&s(&["issuer_signed_cbor"])));
  assert_eq!(cred.sig_structure, unhex(&s(&["issuer_auth", "sig_structure"])));
  let issuer_key = PublicKey {
    x: arr(&s(&["keys", "document_signer", "x"])),
    y: arr(&s(&["keys", "document_signer", "y"])),
  };
  let seed: [u8; 16] = arr(&s(&["holder_openings", "secret_seed"]));
  let birth: [u8; 10] = s(&["holder_openings", "birth_date"]).as_bytes().try_into().unwrap();
  let vi = pseudonym::verifier_input(&s(&["expected", "pseudonym_inputs", "verifier_id"]));
  let witness = BscWitness::new(
    &cred.sig_structure,
    &cred.item,
    &seed,
    &birth,
    &vi,
    issuer_key,
    cred.issuer_signature,
  )
  .unwrap();
  let drs = unhex(&s(&["sessions", session, "device_signature_r_s"]));
  let public = BscPublic {
    issuer_key,
    born_from: born_from.map(date),
    born_by: born_by.map(date),
    now: time(&s(&["expected", "age_check", "proof_time"])),
    challenge: sha256(&unhex(&s(&["sessions", session, "device_sig_structure"]))),
    doc_type: Pattern::doc_type(DOC_TYPE).unwrap(),
    verifier_input: vi,
    pseudonym: pseudonym::pseudonym(&seed, &vi),
  };
  assert_eq!(
    public.pseudonym,
    arr::<32>(&s(&["expected", "pseudonyms_sha256", "known-offender-matching-ssc"]))
  );
  Case {
    witness,
    public,
    device_signature: Signature::from_rs(
      &drs[..32].try_into().unwrap(),
      &drs[32..].try_into().unwrap(),
    ),
  }
}

fn honest() -> Case {
  vector_case(
    &json("nym_auth_test_vectors.json"),
    "redirect",
    Some("2008-10-28"),
    Some("2013-10-27"),
  )
}

#[test]
fn rulebook_vectors_both_variants_both_sessions() {
  for file in ["nym_auth_test_vectors.json", "nym_auth_test_vectors_zero_psc.json"] {
    let v = json(file);
    for session in ["redirect", "dcapi"] {
      for c in v["expected"]["age_check"]["cases"].as_array().unwrap() {
        let case = vector_case(&v, session, c["E"].as_str(), c["C"].as_str());
        let broken = case.broken();
        if c["holds"].as_bool().unwrap() {
          assert_eq!(broken, None, "{file} {session} {}", c["range"]);
        } else {
          let b = broken.unwrap_or_else(|| panic!("{file} {session} {} holds", c["range"]));
          assert!(b.contains("born"), "{file} {session} {}: {b}", c["range"]);
        }
      }
      let case = vector_case(&v, session, None, None);
      for step in app::steps(&case.witness.table) {
        assert_eq!(app::first_broken(&step).unwrap(), None, "{file} step {}", step.position);
      }
    }
  }
}

/// A constraint system that records the values the circuits' own gadgets compute: it is not a
/// witness generator, so no native path runs.
#[derive(Default)]
struct Record {
  aux: Vec<t256::Scalar>,
  inputs: Vec<t256::Scalar>,
}

impl ConstraintSystem<t256::Scalar> for Record {
  type Root = Self;

  fn alloc<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
  where
    F: FnOnce() -> Result<t256::Scalar, SynthesisError>,
    A: FnOnce() -> AR,
    AR: Into<String>,
  {
    self.aux.push(f()?);
    Ok(Variable::new_unchecked(Index::Aux(self.aux.len() - 1)))
  }

  fn alloc_input<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
  where
    F: FnOnce() -> Result<t256::Scalar, SynthesisError>,
    A: FnOnce() -> AR,
    AR: Into<String>,
  {
    self.inputs.push(f()?);
    Ok(Variable::new_unchecked(Index::Input(self.inputs.len())))
  }

  fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, _: LA, _: LB, _: LC)
  where
    A: FnOnce() -> AR,
    AR: Into<String>,
    LA: FnOnce(LinearCombination<t256::Scalar>) -> LinearCombination<t256::Scalar>,
    LB: FnOnce(LinearCombination<t256::Scalar>) -> LinearCombination<t256::Scalar>,
    LC: FnOnce(LinearCombination<t256::Scalar>) -> LinearCombination<t256::Scalar>,
  {
  }

  fn push_namespace<NR, N>(&mut self, _: N)
  where
    NR: Into<String>,
    N: FnOnce() -> NR,
  {
  }

  fn pop_namespace(&mut self) {}

  fn get_root(&mut self) -> &mut Self::Root {
    self
  }
}

fn record<C: VegaCircuit<vega_prover::provider::T256HyraxEngine>>(c: &C) -> Record {
  let mut cs = Record::default();
  let shared = c.shared(&mut cs).unwrap();
  let pre = c.precommitted(&mut cs, &shared).unwrap();
  c.synthesize(&mut cs, &shared, &pre, Some(&[])).unwrap();
  cs
}

#[test]
fn native_witness_is_the_gadgets_value_for_value() {
  for case in [
    honest(),
    vector_case(&json("nym_auth_test_vectors_zero_psc.json"), "dcapi", None, Some("2010-10-27")),
  ] {
    let core = case.core();
    let steps = app::steps(&case.witness.table);
    let w = app::witness(&steps, &core).unwrap();
    let r = record(&core);
    let native: Vec<_> = [&w.shared.private, &w.core.precommitted.private, &w.core.rest.private]
      .into_iter()
      .flatten()
      .copied()
      .collect();
    assert_eq!(r.aux.len(), native.len(), "core values");
    assert!(r.aux == native, "the core's native values differ from the gadgets'");
    let inputs: Vec<_> =
      [&w.core.precommitted.public, &w.core.rest.public].into_iter().flatten().copied().collect();
    assert_eq!(r.inputs, inputs);
    assert_eq!(w.core.public_values, case.public.values());
    for (step, instance) in steps.iter().zip(&w.steps) {
      let r = record(step);
      let native: Vec<_> = [&w.shared.private, &instance.precommitted.private]
        .into_iter()
        .flatten()
        .copied()
        .collect();
      assert!(r.aux == native, "step {}", step.position);
      assert_eq!(r.inputs, instance.precommitted.public);
    }
  }
}

#[test]
fn proves_accepts_and_refuses() {
  let case = honest();
  let (pk, vk) = app::setup(&BscCore::blank()).unwrap();
  let core = case.core();
  let steps = app::steps(&case.witness.table);
  let w = app::witness(&steps, &core).unwrap();
  let prepared = app::prepare(&pk, &w.steps(), &w.core()).unwrap();
  let (proof, _) = app::prove(&pk, &w.steps(), &w.core(), prepared).unwrap();
  let named = case.public.named_values();
  assert_eq!(app::accept_pseudonym(&BSC_MDOC, &vk, &proof, &named).unwrap(), case.public.pseudonym);

  // Another proof_time, another range, another session or verifier: other public values.
  for change in 0..4 {
    let mut p = case.public.clone();
    match change {
      0 => p.now.second += 1,
      1 => p.born_by = None,
      2 => p.challenge[0] ^= 1,
      _ => p.verifier_input[31] ^= 1,
    }
    assert!(
      app::accept_pseudonym(&BSC_MDOC, &vk, &proof, &p.named_values()).is_err(),
      "change {change}"
    );
  }

  // A changed byte of the proof.
  let bytes = bincode::serialize(&proof).unwrap();
  for at in [100, bytes.len() / 2, bytes.len() - 40] {
    let mut b = bytes.clone();
    b[at] ^= 1;
    if let Ok(p) = bincode::deserialize::<app::Proof>(&b) {
      assert!(app::accept_pseudonym(&BSC_MDOC, &vk, &p, &named).is_err(), "byte {at}");
    }
  }

  // The keys from the circuits as data are the setup's.
  let raw = app::shapes(&BscCore::blank()).unwrap();
  let (pk2, vk2) = app::setup_from_shapes_in(&BSC_MDOC, &raw).unwrap();
  assert_eq!(bincode::serialize(&vk2).unwrap(), bincode::serialize(&vk).unwrap());
  assert_eq!(bincode::serialize(&pk2).unwrap(), bincode::serialize(&pk).unwrap());
}

/// The SHA-256 of the circuits as data (uncompressed): the v0.5 core's, and the v0.4 cores',
/// which the table's per-layout positions must leave as they were.
#[test]
fn shapes_are_fixed() {
  use sha2::Digest;
  let h = |raw: Vec<u8>| {
    sha2::Sha256::digest(&raw).iter().map(|b| format!("{b:02x}")).collect::<String>()
  };
  assert_eq!(h(app::shapes(&BscCore::blank()).unwrap()), BSC_SHAPES_RAW_SHA256);
  assert_eq!(h(app::shapes(&vega_age::mdoc::MdocNymCore::blank()).unwrap()), V04_MDOC_RAW_SHA256);
  assert_eq!(
    h(app::shapes(&vega_age::sdjwt::SdJwtNymCore::blank()).unwrap()),
    V04_SD_JWT_RAW_SHA256
  );
}

const BSC_SHAPES_RAW_SHA256: &str =
  "1256a4a219c8cc9f05433370dd7e9572318383cba58d8abe58b4f67bc4711463";
const V04_MDOC_RAW_SHA256: &str =
  "4da5e73afb9be2682e70be793c9956a73304e21f31246aa10da0d3e95c926425";
const V04_SD_JWT_RAW_SHA256: &str =
  "eb8c4dd35a96dc681cfc7e821af5df8b24c0ad7e33424f8b2bd3d7e324662e53";

#[test]
fn synthetic_holders_and_age_edges() {
  let v = json("nym_auth_test_vectors.json");
  let issuer_key = PublicKey {
    x: arr(v["keys"]["document_signer"]["x"].as_str().unwrap()),
    y: arr(v["keys"]["document_signer"]["y"].as_str().unwrap()),
  };
  // (holder, proof_time, E, C, holds)
  let cases = [
    ("B", "2026-10-28T09:00:00Z", None, Some("2008-10-28"), true),
    ("B", "2026-10-27T23:59:59Z", None, Some("2008-10-27"), false),
    ("C", "2026-10-28T09:00:00Z", Some("2008-10-29"), Some("2013-10-28"), true),
    ("C", "2026-10-28T09:00:00Z", None, Some("2011-10-28"), false),
    ("D", "2026-10-28T09:00:00Z", None, Some("2008-10-28"), true),
    ("D", "2026-10-28T09:00:00Z", None, None, true),
  ];
  for (h, t, e, c, holds) in cases {
    let d = json(&format!("synthetic/holder{h}.json"));
    let cred = parse(&unhex(d["issuer_signed"].as_str().unwrap()));
    let seed: [u8; 16] = arr(d["secret_seed"].as_str().unwrap());
    let birth: [u8; 10] = d["birth_date"].as_str().unwrap().as_bytes().try_into().unwrap();
    let vi = pseudonym::verifier_input("x509_san_dns:verifier.example");
    let witness = BscWitness::new(
      &cred.sig_structure,
      &cred.item,
      &seed,
      &birth,
      &vi,
      issuer_key,
      cred.issuer_signature,
    )
    .unwrap();
    let device = KeyPair::from_secret(&arr(d["device_d"].as_str().unwrap())).unwrap();
    let message = b"a device message".to_vec();
    let public = BscPublic {
      issuer_key,
      born_from: e.map(date),
      born_by: c.map(date),
      now: time(t),
      challenge: sha256(&message),
      doc_type: Pattern::doc_type(DOC_TYPE).unwrap(),
      verifier_input: vi,
      pseudonym: pseudonym::pseudonym(&seed, &vi),
    };
    let case = Case { witness, public, device_signature: device.sign(&message).for_rules() };
    let broken = case.broken();
    assert_eq!(broken.is_none(), holds, "holder {h} at {t}: {broken:?}");
    if let Some(b) = broken {
      assert!(b.contains("born"), "{b}");
    }
  }
}

#[test]
fn fixture_issuer_gives_the_profile() {
  let issuer = KeyPair::from_label("bsc issuer");
  let device = KeyPair::from_label("bsc device");
  let from = time("2026-10-01T00:00:00Z");
  let until = time("2027-10-01T00:00:00Z");
  let seed = [7u8; 16];
  let birth = *b"2009-02-28";
  let mdoc = issue_bsc(&issuer, &device.public, &from, &until, &seed, &birth, [0; 32], "fixture");
  assert_eq!((mdoc.sig_structure.len(), mdoc.item("bsc").len()), (423, 108));
  let vi = pseudonym::verifier_input("x509_san_dns:rp.example");
  let witness = BscWitness::new(
    &mdoc.sig_structure,
    mdoc.item("bsc"),
    &seed,
    &birth,
    &vi,
    issuer.public,
    mdoc.signature.for_rules(),
  )
  .unwrap();
  let message = b"device".to_vec();
  let public = BscPublic {
    issuer_key: issuer.public,
    born_from: Some(date("2008-10-02")),
    born_by: Some(date("2013-10-01")),
    now: from,
    challenge: sha256(&message),
    doc_type: Pattern::doc_type(DOC_TYPE).unwrap(),
    verifier_input: vi,
    pseudonym: pseudonym::pseudonym(&seed, &vi),
  };
  let case = Case { witness, public, device_signature: device.sign(&message).for_rules() };
  assert_eq!(case.broken(), None);
  // Both validity bounds are included; a second outside either is refused.
  for (t, expect) in [
    ("2026-10-01T00:00:00Z", None),
    ("2027-10-01T00:00:00Z", None),
    ("2026-09-30T23:59:59Z", Some("validity started")),
    ("2027-10-01T00:00:01Z", Some("not expired")),
  ] {
    let mut c = case.clone();
    c.public.now = time(t);
    let b = c.broken();
    match expect {
      None => assert_eq!(b, None, "{t}"),
      Some(rule) => assert!(b.as_deref().is_some_and(|b| b.contains(rule)), "{t}: {b:?}"),
    }
  }
}

/// Each dishonest witness or presentation, and the rule it breaks first.
#[test]
fn red_team() {
  let v = json("nym_auth_test_vectors.json");
  let sig = unhex(v["issuer_auth"]["sig_structure"].as_str().unwrap());
  let item = unhex(v["issuer_signed_items"][0]["item_bytes_tag24"].as_str().unwrap());
  let psc_item = unhex(v["issuer_signed_items"][1]["item_bytes_tag24"].as_str().unwrap());
  let honest = honest();
  assert_eq!(honest.broken(), None);
  let messages =
    |seed: &[u8; 16], birth: &[u8; 10], opening_bytes: Option<Vec<u8>>| -> Vec<(Region, Vec<u8>)> {
      let vi = honest.public.verifier_input;
      vec![
        (ITEM, item.clone()),
        (OPENING, opening_bytes.unwrap_or_else(|| opening(seed, birth).to_vec())),
        (NYM, pseudonym::message(seed, &vi)),
      ]
    };
  let seed: [u8; 16] = arr(v["holder_openings"]["secret_seed"].as_str().unwrap());
  let birth: [u8; 10] =
    v["holder_openings"]["birth_date"].as_str().unwrap().as_bytes().try_into().unwrap();
  let table_of = |skipped: usize, m: Vec<(Region, Vec<u8>)>| {
    let m: Vec<(Region, &[u8])> = m.iter().map(|(r, b)| (*r, &b[..])).collect();
    Arc::new(Table::with_messages(BSC_MDOC, &sig, skipped, &m).unwrap())
  };

  let mut cases: Vec<(&str, Case, &str)> = Vec::new();
  let mut add = |name, f: &dyn Fn(&mut Case), rule| {
    let mut c = honest.clone();
    f(&mut c);
    cases.push((name, c, rule));
  };

  // The Sig_structure from a pseudo-preimage start: one block skipped, the start state its state.
  add(
    "start state not the initial value",
    &|c: &mut Case| {
      c.witness.table = table_of(1, messages(&seed, &birth, None));
      for at in [
        &mut c.witness.doc_type_at,
        &mut c.witness.digest_at,
        &mut c.witness.device_key_at,
        &mut c.witness.valid_from_at,
        &mut c.witness.valid_until_at,
      ] {
        *at -= 64;
      }
    },
    "start state half",
  );
  add("a shorter length", &|c: &mut Case| c.witness.signed_len -= 1, "Sig_structure padding");
  add("a longer length", &|c: &mut Case| c.witness.signed_len += 1, "Sig_structure padding");
  add(
    "a read past the message's end",
    &|c: &mut Case| c.witness.valid_until_at = c.witness.signed_len - 32,
    "valid until",
  );
  add(
    "the docType read past the end",
    &|c: &mut Case| c.witness.doc_type_at = c.witness.signed_len - 47,
    "doc type",
  );
  add(
    "a byte written into the padding",
    &|c: &mut Case| {
      let mut blocks = c.witness.table.blocks.clone();
      let l = c.witness.signed_len;
      blocks[l / 64][l % 64 + 2] = 0x41;
      let start = c.witness.table.start;
      c.rechained(blocks, start);
    },
    "Sig_structure padding",
  );
  add(
    "the bsc item at a shorter length",
    &|c: &mut Case| c.witness.item_len -= 1,
    "bsc item padding",
  );
  add(
    "the bsc listing pointed at psc's",
    &|c: &mut Case| {
      let listed = [&b"\x58\x20"[..], &sha256(&psc_item)].concat();
      c.witness.digest_at = sig.windows(34).position(|w| w == &listed[..]).unwrap();
    },
    "bsc digest half",
  );
  add(
    "the identifier read at the value",
    &|c: &mut Case| c.witness.identifier_at = c.witness.value_at,
    "bsc identifier bytes",
  );
  add(
    "another birth date in the opening",
    &|c: &mut Case| {
      c.witness.table = table_of(0, messages(&seed, b"2001-05-17", None));
    },
    "opening digest half",
  );
  add(
    "another seed in the opening",
    &|c: &mut Case| {
      let mut other = seed;
      other[0] ^= 1;
      c.witness.table = table_of(0, messages(&other, &birth, None));
    },
    "opening digest half",
  );
  add(
    "an opening of 27 bytes",
    &|c: &mut Case| {
      let mut o = opening(&seed, &birth).to_vec();
      o.push(b'0');
      c.witness.table = table_of(0, messages(&seed, &birth, Some(o)));
    },
    "opening chunk 1",
  );
  add(
    "the device key read one byte off",
    &|c: &mut Case| c.witness.device_key_at += 1,
    "device key head",
  );
  add(
    "validFrom read at validUntil",
    &|c: &mut Case| c.witness.valid_from_at = c.witness.valid_until_at,
    "valid from",
  );
  add(
    "another device signature",
    &|c: &mut Case| {
      let drs = unhex(v["sessions"]["dcapi"]["device_signature_r_s"].as_str().unwrap());
      c.device_signature =
        Signature::from_rs(&drs[..32].try_into().unwrap(), &drs[32..].try_into().unwrap());
    },
    "device signature",
  );
  add(
    "another issuer key",
    &|c: &mut Case| {
      c.public.issuer_key = PublicKey {
        x: arr(v["keys"]["device"]["x"].as_str().unwrap()),
        y: arr(v["keys"]["device"]["y"].as_str().unwrap()),
      };
    },
    "same issuer key",
  );
  add(
    "another docType",
    &|c: &mut Case| c.public.doc_type = Pattern::doc_type("eu.europa.ec.eudi.pid.1").unwrap(),
    "type",
  );
  add(
    "another verifier_input",
    &|c: &mut Case| c.public.verifier_input[0] ^= 1,
    "pseudonym/verifier input",
  );
  add("another pseudonym", &|c: &mut Case| c.public.pseudonym[31] ^= 1, "pseudonym/pseudonym low");
  add(
    "an age outside the range",
    &|c: &mut Case| c.public.born_by = Some(date("2008-10-27")),
    "born by the cutoff",
  );

  for (name, case, rule) in &cases {
    let broken = case.broken();
    assert!(
      broken.as_deref().is_some_and(|b| b.contains(rule)),
      "{name}: expected {rule}, got {broken:?}"
    );
    println!("refused: {name}: {}", broken.unwrap());
  }
  assert_eq!(cases.len(), 20);
}

/// The shipped golden proof (tests/golden, written once) verifies with its values, and with no
/// other: every verifier of these circuits, on any platform, accepts exactly this.
#[test]
fn golden_proof() {
  let g = json("../golden/bsc_redirect_13-17.json");
  let s = |k: &str| g[k].as_str().unwrap().to_string();
  let public = BscPublic {
    issuer_key: PublicKey {
      x: arr(g["issuer_key"]["x"].as_str().unwrap()),
      y: arr(g["issuer_key"]["y"].as_str().unwrap()),
    },
    born_from: Some(date(&s("born_from"))),
    born_by: Some(date(&s("born_by"))),
    now: time(&s("proof_time")),
    challenge: arr(&s("challenge")),
    doc_type: Pattern::doc_type(&s("doc_type")).unwrap(),
    verifier_input: pseudonym::verifier_input(&s("verifier_id")),
    pseudonym: arr(&s("pseudonym")),
  };
  assert_eq!(public.verifier_input, arr::<32>(&s("verifier_input")));
  let raw = app::shapes(&BscCore::blank()).unwrap();
  let (_, vk) = app::setup_from_shapes_in(&BSC_MDOC, &raw).unwrap();
  let proof: app::Proof = bincode::deserialize(&unhex(&s("proof"))).unwrap();
  assert_eq!(
    app::accept_pseudonym(&BSC_MDOC, &vk, &proof, &public.named_values()).unwrap(),
    public.pseudonym
  );
  let mut other = public.clone();
  other.born_from = None;
  assert!(app::accept_pseudonym(&BSC_MDOC, &vk, &proof, &other.named_values()).is_err());
}

/// Two phases, as a wallet runs them: the prover prepares (commits the table and the credential's
/// rules) from the core without its presentation, before the device signature exists, then proves
/// with it. The prepared state serves the next presentation to the same verifier too.
#[test]
fn prepare_before_the_signature() {
  let case = honest();
  let (pk, vk) = app::setup(&BscCore::blank()).unwrap();
  let steps = app::steps(&case.witness.table);
  let unsigned = BscCore { witness: Some(Arc::new(case.witness.clone())), presentation: None };
  let prepared = app::prepare(&pk, &steps, &unsigned).unwrap();
  let (proof, next) = app::prove(&pk, &steps, &case.core(), prepared).unwrap();
  let named = case.public.named_values();
  assert_eq!(app::accept_pseudonym(&BSC_MDOC, &vk, &proof, &named).unwrap(), case.public.pseudonym);
  // The next presentation to the same verifier, at another proof_time and with another challenge.
  let mut later = case.clone();
  later.public.now.second += 30;
  let dcapi = json("nym_auth_test_vectors.json")["sessions"]["dcapi"].clone();
  later.public.challenge = sha256(&unhex(dcapi["device_sig_structure"].as_str().unwrap()));
  let drs = unhex(dcapi["device_signature_r_s"].as_str().unwrap());
  later.device_signature =
    Signature::from_rs(&drs[..32].try_into().unwrap(), &drs[32..].try_into().unwrap());
  let (proof2, _) = app::prove(&pk, &steps, &later.core(), next).unwrap();
  let named2 = later.public.named_values();
  assert_eq!(
    app::accept_pseudonym(&BSC_MDOC, &vk, &proof2, &named2).unwrap(),
    case.public.pseudonym
  );
  assert!(app::accept_pseudonym(&BSC_MDOC, &vk, &proof2, &named).is_err());
}
