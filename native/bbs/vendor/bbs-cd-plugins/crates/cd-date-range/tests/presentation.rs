//! Honest presentations through the envelope: thresholds, ranges, boundaries,
//! request checks and the holder policy.
mod common;

use bbs_cd_plugin::Error;
use cd_date_range::{DateRangeParams, DateRangeProver};
use common::*;

fn accepts(born: &str, p: DateRangeParams) -> bool {
    let w = world(born);
    let req = w.request(&p);
    match w.present(&req) {
        Ok(b) => {
            let v = w.verify(&req, &b).expect("an honest proof verifies");
            assert_eq!(v.outputs, vec![p.encode()]);
            assert_eq!(v.disclosed[0], vec![("nationality".to_string(), b"SE".to_vec())]);
            true
        }
        Err(Error::Prover(_)) => false,
        Err(e) => panic!("unexpected error {e}"),
    }
}

#[test]
fn at_least_18() {
    let p = DateRangeParams::le(20081018);
    assert!(accepts("1990-05-17", p));
    assert!(accepts("2008-10-18", p), "18th birthday today");
    assert!(!accepts("2008-10-19", p), "18 tomorrow");
    assert!(accepts("1900-01-01", p), "lower edge of the encoding");
}

#[test]
fn younger_than_25() {
    let p = DateRangeParams::ge(20011019);
    assert!(accepts("2001-10-19", p));
    assert!(accepts("2010-01-01", p));
    assert!(!accepts("2001-10-18", p), "25 today");
}

#[test]
fn between_18_and_24() {
    let p = DateRangeParams::between(20011019, 20081018);
    assert!(accepts("2001-10-19", p));
    assert!(accepts("2005-06-30", p));
    assert!(accepts("2008-10-18", p));
    assert!(!accepts("2001-10-18", p));
    assert!(!accepts("2008-10-19", p));
}

#[test]
fn nonexistent_cutoff_day() {
    // on 2028-02-29 an 18+ verifier subtracts 18 from the year
    let p = DateRangeParams::le(20100229);
    assert!(accepts("2010-02-28", p));
    assert!(!accepts("2010-03-01", p));
}

#[test]
fn leap_day_birthdays() {
    let p = DateRangeParams::le(20080229);
    assert!(accepts("2008-02-29", p));
    assert!(accepts("2008-02-28", p));
    assert!(!accepts("2008-03-01", p));
}

#[test]
fn clamped_upper_bound() {
    // le beyond the attribute's range: hi = 2^17 − 1
    assert!(accepts("2252-05-04", DateRangeParams::le(99991231)));
    // 16-bit attribute
    let w = world_bits("2076-03-02", 16);
    let req = w.request(&DateRangeParams::le(20800101));
    let b = w.present(&req).unwrap();
    w.verify(&req, &b).unwrap();
}

#[test]
fn proof_sizes() {
    let w = world("1990-05-17");
    let (_, spec, _) = w.iss.params.schema.find(ATTR).unwrap();
    for (p, k) in [
        (DateRangeParams::le(20081018), 16),
        (DateRangeParams::ge(20011019), 17),
        (DateRangeParams::between(20011019, 20081018), 12),
        (DateRangeParams::le(20760302), 16),
        (DateRangeParams::le(20760303), 17),
    ] {
        assert_eq!(cd_date_range::proof_len(spec, &p.encode()).unwrap(), 36 + 144 * k, "{p}");
    }
}

#[test]
fn verifier_rejects_bad_requests() {
    let w = world("1990-05-17");
    let le = 20081018u32.to_be_bytes();
    for params in [
        vec![],
        [&[0u8][..], &le].concat(),
        [&[2u8][..], &le, &[0u8]].concat(),
        [&[2u8][..], &19001301u32.to_be_bytes()].concat(),
        [&[2u8][..], &18991231u32.to_be_bytes()].concat(),
        DateRangeParams::between(20081018, 20011019).encode(),
        DateRangeParams::between(20081018, 20081018).encode(),
    ] {
        let req = w.request_raw(params.clone());
        assert!(verifier().check_request(&w.issuers(), &req).is_err(), "{params:?}");
        // and the honest prover refuses it
        assert!(w.present(&req).is_err(), "{params:?}");
    }
}

#[test]
fn holder_policy_refuses_narrow_windows() {
    let w = world("2005-06-30");
    let narrow = DateRangeParams::between(20050601, 20050731);
    let req = w.request(&narrow);
    assert!(matches!(w.present(&req), Err(Error::Prover(_))));
    // with the policy off, the proof is valid: the policy is the holder's only defence
    let b = w.present_with(&req, Box::new(DateRangeProver::with_min_window(0))).unwrap();
    w.verify(&req, &b).unwrap();
    // one year exactly is allowed by default
    let year = DateRangeParams::between(20050101, 20051231);
    assert_eq!(year.bounds(17).unwrap().1 - year.bounds(17).unwrap().0 + 1, 372);
    let req = w.request(&year);
    w.verify(&req, &w.present(&req).unwrap()).unwrap();
}

#[test]
fn two_presentations_are_unlinkable_in_bytes() {
    let w = world("1990-05-17");
    let req = w.request(&DateRangeParams::le(20081018));
    let a = w.present(&req).unwrap();
    let b = w.present(&req).unwrap();
    assert_eq!(a.len(), b.len());
    // the plugin proofs (at the end) share only the magic
    let n = cd_date_range::range::proof_len(16);
    let (pa, pb) = (&a[a.len() - n..], &b[b.len() - n..]);
    assert_eq!(&pa[..4], &pb[..4]);
    assert_ne!(&pa[4..36], &pb[4..36]);
    for i in 0..16 {
        let o = 36 + 144 * i;
        assert_ne!(&pa[o..o + 48], &pb[o..o + 48], "digit commitment {i}");
    }
}
