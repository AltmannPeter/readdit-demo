//! The lengths the compact profile allows, from the independent review of the v0.5 core:
//! completeness at every Sig_structure length (376 to 439) and every bsc item length that holds
//! both reads (69 to 119), with the reads ending exactly at the length; the padding at every wrong
//! length; a self-consistent other length caught at the digest; reads one byte past the length;
//! and the unused table positions, which nothing reads.

use std::sync::Arc;

use vega_age::app;
use vega_age::bsc::{
  BSC_IDENTIFIER, BSC_MDOC, BscCore, BscPresentation, BscPublic, BscWitness, DOC_TYPE, ITEM, NYM,
  OPENING, opening,
};
use vega_age::fixtures::KeyPair;
use vega_age::mdoc::{DEVICE_KEY, DEVICE_KEY_Y, VALID_FROM, VALID_UNTIL};
use vega_age::presentation::{Date, Time};
use vega_age::pseudonym::{self, MDOC_VALUE};
use vega_age::request::Pattern;
use vega_age::table::{Region, Table, pad, sha256};

const SEED: [u8; 16] = *b"0123456789abcdef";
const BIRTH: [u8; 10] = *b"2009-02-28";

fn t(y: u32, mo: u32, d: u32) -> Time {
  Time { date: Date { year: y, month: mo, day: d }, hour: 0, minute: 0, second: 0 }
}

/// An item of `n` bytes holding the identifier and the value; `ident_first` puts the identifier
/// at 0 and the value ending at n, else the value at 0 and the identifier ending at n.
fn item(n: usize, ident_first: bool) -> Vec<u8> {
  let bsc = sha256(&opening(&SEED, &BIRTH));
  let value = [MDOC_VALUE, &bsc].concat();
  let fill = n.checked_sub(BSC_IDENTIFIER.len() + value.len()).expect("fits");
  let filler = vec![0u8; fill];
  if ident_first {
    [BSC_IDENTIFIER, &filler, &value].concat()
  } else {
    [&value[..], &filler, BSC_IDENTIFIER].concat()
  }
}

/// A Sig_structure of `l` bytes with the patterns the core reads; `doc_first` puts the docType
/// window at 0 and validUntil ending at l, else validUntil at 0 and the docType ending at l.
fn sig(l: usize, item: &[u8], device: &KeyPair, doc_first: bool) -> Vec<u8> {
  let doc = [&[0xaau8; 10][..], b"\x67docType", &[0x78, DOC_TYPE.len() as u8], DOC_TYPE.as_bytes()]
    .concat();
  assert_eq!(doc.len(), 48);
  let listing = [&b"\x58\x20"[..], &sha256(item)].concat();
  let dk = [DEVICE_KEY, &device.public.x, DEVICE_KEY_Y, &device.public.y].concat();
  let vf = [VALID_FROM, b"2026-01-01T00:00:00Z"].concat();
  let vu = [VALID_UNTIL, b"2030-01-01T00:00:00Z"].concat();
  let used = doc.len() + listing.len() + dk.len() + vf.len() + vu.len();
  let filler = vec![0u8; l.checked_sub(used).expect("fits")];
  let s = if doc_first {
    [doc, listing, dk, vf, filler, vu].concat()
  } else {
    [vu, vf, listing, dk, filler, doc].concat()
  };
  assert_eq!(s.len(), l);
  s
}

struct Fx {
  issuer: KeyPair,
  device: KeyPair,
}

fn fx() -> Fx {
  Fx { issuer: KeyPair::from_label("review issuer"), device: KeyPair::from_label("review device") }
}

fn core_for(f: &Fx, s: &[u8], it: &[u8]) -> Result<BscCore, String> {
  let vi = pseudonym::verifier_input("x509_san_dns:rp.example");
  let witness =
    BscWitness::new(s, it, &SEED, &BIRTH, &vi, f.issuer.public, f.issuer.sign(s).for_rules())?;
  let m = b"challenge".to_vec();
  let public = BscPublic {
    issuer_key: f.issuer.public,
    born_from: Some(Date { year: 2008, month: 10, day: 28 }),
    born_by: Some(Date { year: 2013, month: 10, day: 27 }),
    now: t(2027, 1, 1),
    challenge: sha256(&m),
    doc_type: Pattern::doc_type(DOC_TYPE).unwrap(),
    verifier_input: vi,
    pseudonym: pseudonym::pseudonym(&SEED, &vi),
  };
  Ok(BscCore {
    witness: Some(Arc::new(witness)),
    presentation: Some(BscPresentation { public, device_signature: f.device.sign(&m).for_rules() }),
  })
}

fn steps_ok(core: &BscCore) -> bool {
  app::steps(&core.witness.as_ref().unwrap().table)
    .iter()
    .all(|s| app::first_broken(s).unwrap().is_none())
}

#[test]
fn completeness_every_signed_length() {
  let f = fx();
  let it = item(108, true);
  for l in 376..=439 {
    for doc_first in [true, false] {
      let s = sig(l, &it, &f.device, doc_first);
      let core = core_for(&f, &s, &it).unwrap();
      assert_eq!(app::first_broken(&core).unwrap(), None, "L={l} doc_first={doc_first}");
      assert!(steps_ok(&core), "steps L={l}");
    }
  }
  // Lengths outside the range are refused by the witness.
  for l in [375, 440] {
    let s = sig(l, &it, &f.device, true);
    assert!(core_for(&f, &s, &it).is_err());
  }
}

#[test]
fn completeness_every_item_length() {
  let f = fx();
  for n in 69..=119 {
    for ident_first in [true, false] {
      let it = item(n, ident_first);
      for l in [376, 423, 439] {
        let s = sig(l, &it, &f.device, true);
        let core = core_for(&f, &s, &it).unwrap();
        assert_eq!(app::first_broken(&core).unwrap(), None, "n={n} ident_first={ident_first}");
        assert!(steps_ok(&core));
      }
    }
  }
}

/// Item lengths 56..68 cannot hold both windows (22 + 47 bytes); the padding gadget still
/// accepts them: the first broken rule is a read, never the padding.
#[test]
fn padding_gadget_short_items() {
  let f = fx();
  let big = item(108, true);
  let s0 = sig(423, &big, &f.device, true);
  let honest = core_for(&f, &s0, &big).unwrap();
  for n in 56..=68 {
    let bsc = sha256(&opening(&SEED, &BIRTH));
    let mut it = vec![0u8; n];
    it[n - 47..n - 32].copy_from_slice(MDOC_VALUE);
    it[n - 32..].copy_from_slice(&bsc);
    let s = sig(423, &it, &f.device, true);
    let mut w = (**honest.witness.as_ref().unwrap()).clone();
    let vi = honest.presentation.as_ref().unwrap().public.verifier_input;
    let msgs: Vec<(Region, Vec<u8>)> = vec![
      (ITEM, it.clone()),
      (OPENING, opening(&SEED, &BIRTH).to_vec()),
      (NYM, pseudonym::message(&SEED, &vi)),
    ];
    let m: Vec<(Region, &[u8])> = msgs.iter().map(|(r, b)| (*r, &b[..])).collect();
    w.table = Arc::new(Table::with_messages(BSC_MDOC, &s, 0, &m).unwrap());
    w.item_len = n;
    w.issuer_signature = f.issuer.sign(&s).for_rules();
    w.identifier_at = 0;
    w.value_at = n - 47;
    let c = BscCore { witness: Some(Arc::new(w)), presentation: honest.presentation.clone() };
    let b = app::first_broken(&c).unwrap();
    assert!(b.as_deref().is_some_and(|b| b.contains("bsc identifier bytes")), "n={n}: {b:?}");
  }
}

/// Every wrong private length, for both regions: the padding rule breaks.
#[test]
fn every_wrong_length_breaks_padding() {
  let f = fx();
  let it = item(108, true);
  for l in [376, 383, 384, 423, 439] {
    let s = sig(l, &it, &f.device, true);
    let honest = core_for(&f, &s, &it).unwrap();
    for wrong in 376..=439 {
      if wrong == l {
        continue;
      }
      let mut w = (**honest.witness.as_ref().unwrap()).clone();
      w.signed_len = wrong;
      let c = BscCore { witness: Some(Arc::new(w)), presentation: honest.presentation.clone() };
      let b = app::first_broken(&c).unwrap().unwrap();
      assert!(b.contains("Sig_structure padding"), "L={l} wrong={wrong}: {b}");
    }
    for wrong in 56..=119 {
      if wrong == 108 {
        continue;
      }
      let mut w = (**honest.witness.as_ref().unwrap()).clone();
      w.item_len = wrong;
      let c = BscCore { witness: Some(Arc::new(w)), presentation: honest.presentation.clone() };
      let b = app::first_broken(&c).unwrap().unwrap();
      assert!(b.contains("bsc item padding"), "item wrong={wrong}: {b}");
    }
  }
}

/// A prover's own table: the region holds a message M' of length L' with valid padding at L',
/// where M' is the honest message's padded bytes cut at L' (so it starts with the real message
/// and may include its 0x80 and zeros). The padding rules pass; the digest no longer matches.
#[test]
fn self_consistent_other_lengths_fail_at_digest() {
  let f = fx();
  let it = item(100, true);
  let s = sig(400, &it, &f.device, true);
  let honest = core_for(&f, &s, &it).unwrap();
  let padded_item = pad(&it);
  for l2 in 101..=119 {
    let m2 = padded_item[..l2].to_vec();
    let mut w = (**honest.witness.as_ref().unwrap()).clone();
    let vi = honest.presentation.as_ref().unwrap().public.verifier_input;
    let msgs: Vec<(Region, Vec<u8>)> = vec![
      (ITEM, m2.clone()),
      (OPENING, opening(&SEED, &BIRTH).to_vec()),
      (NYM, pseudonym::message(&SEED, &vi)),
    ];
    let m: Vec<(Region, &[u8])> = msgs.iter().map(|(r, b)| (*r, &b[..])).collect();
    w.table = Arc::new(Table::with_messages(BSC_MDOC, &s, 0, &m).unwrap());
    w.item_len = l2;
    let c = BscCore { witness: Some(Arc::new(w)), presentation: honest.presentation.clone() };
    let b = app::first_broken(&c).unwrap().unwrap();
    assert!(b.contains("bsc digest half"), "l2={l2}: {b}");
  }
}

/// Reads ending one byte past L in the item (value) and in the Sig_structure (docType, the
/// listing, the device key): refused at the read's range check.
#[test]
fn reads_one_past_length() {
  let f = fx();
  let it = item(119, true);
  let s = sig(439, &it, &f.device, false); // docType window ends at L
  let honest = core_for(&f, &s, &it).unwrap();
  assert_eq!(app::first_broken(&honest).unwrap(), None);
  let base = (**honest.witness.as_ref().unwrap()).clone();
  let cases: Vec<(&str, Box<dyn Fn(&mut BscWitness)>, &str)> = vec![
    ("value +1", Box::new(|w| w.value_at += 1), "bsc value/inside"),
    ("ident at L-20", Box::new(|w| w.identifier_at = w.item_len - 20), "bsc identifier/inside"),
    ("doc +1", Box::new(|w| w.doc_type_at += 1), "doc type/inside"),
    ("listing at L-33", Box::new(|w| w.digest_at = w.signed_len - 33), "bsc digest/inside"),
    ("dk at L-70", Box::new(|w| w.device_key_at = w.signed_len - 70), "device key/inside"),
  ];
  for (name, f, rule) in cases {
    let mut w = base.clone();
    f(&mut w);
    let c = BscCore { witness: Some(Arc::new(w)), presentation: honest.presentation.clone() };
    let b = app::first_broken(&c).unwrap().unwrap();
    assert!(b.contains(rule), "{name}: {b}");
    println!("{name}: {b}");
  }
}

/// Garbage in the unused positions 12..15 (rechained): every rule still holds, and nothing reads
/// them.
#[test]
fn unused_positions_inert() {
  let f = fx();
  let it = item(108, true);
  let s = sig(423, &it, &f.device, true);
  let honest = core_for(&f, &s, &it).unwrap();
  let mut w = (**honest.witness.as_ref().unwrap()).clone();
  let mut blocks = w.table.blocks.clone();
  for (j, b) in blocks.iter_mut().enumerate().skip(12) {
    b.fill(j as u8 ^ 0x5a);
  }
  w.table = Arc::new(Table::from_blocks_in(BSC_MDOC, blocks, w.table.start));
  let c = BscCore { witness: Some(Arc::new(w)), presentation: honest.presentation.clone() };
  assert_eq!(app::first_broken(&c).unwrap(), None);
  assert!(steps_ok(&c));
}
