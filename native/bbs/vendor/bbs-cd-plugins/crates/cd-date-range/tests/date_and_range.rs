//! The `date-packed` encoding, the issuance handler, the request parameters
//! and the generic range proof (bases, digits, prove/verify).
use bbs_cd::utils::commitment_generators;
use bbs_cd_plugin::issuer::AttrHandler;
use bbs_cd_plugin::issuer::SUITE;
use bbs_cd_plugin::schema::{AttributeSpec, ScalarsSpec};
use bbs_cd_plugin::Error;
use bls12_381::Scalar;
use cd_date_range::date::{days_in_month, is_leap_year};
use cd_date_range::range::{self, Bases, ChallengeInput, Statement};
use cd_date_range::{DateHandler, DateRangeParams, Ymd, TYPE_DATE};
use rand_core::{OsRng, RngCore};

fn ymd(n: u32) -> Ymd {
    Ymd::from_yyyymmdd(n).unwrap()
}

#[test]
fn pack_values() {
    assert_eq!(ymd(19000101).pack(), 0);
    assert_eq!(ymd(19000102).pack(), 1);
    assert_eq!(ymd(19000201).pack(), 31);
    assert_eq!(ymd(19010101).pack(), 372);
    assert_eq!(ymd(20081018).pack(), 40_472);
    assert_eq!(ymd(20261018).pack(), 47_168);
    // last cutoff with a 16-bit one-sided proof
    assert_eq!(ymd(20760302).pack(), 65_535);
    assert_eq!(ymd(20760303).pack(), 65_536);
    // last date of a 17-bit attribute
    assert_eq!(Ymd::unpack((1 << 17) - 1).unwrap(), ymd(22520504));
}

#[test]
fn pack_is_increasing_over_every_calendar_day() {
    let mut prev: Option<u64> = None;
    for y in 1900..=2300u16 {
        for m in 1..=12u8 {
            for d in 1..=days_in_month(y, m) {
                let x = Ymd::new(y, m, d).unwrap();
                let v = x.pack();
                assert!(prev.is_none_or(|p| v > p), "{x}");
                assert_eq!(Ymd::unpack(v), Some(x));
                prev = Some(v);
            }
        }
    }
}

#[test]
fn nonexistent_days_order_correctly() {
    // 2010-02-29 does not exist; as a bound it sits between 02-28 and 03-01
    let (a, b, c) = (ymd(20100228).pack(), ymd(20100229).pack(), ymd(20100301).pack());
    assert!(a < b && b < c);
    assert!(ymd(20100431).pack() < ymd(20100501).pack());
}

#[test]
fn yyyymmdd_field_checks() {
    for bad in [0, 18991231, 19000001, 19001301, 19000100, 19000132, 99991232, 100000101, u32::MAX] {
        assert!(Ymd::from_yyyymmdd(bad).is_none(), "{bad}");
    }
    assert_eq!(ymd(20100229).to_yyyymmdd(), 20100229); // fields only, no calendar
    assert_eq!(ymd(99991231).to_yyyymmdd(), 99991231);
}

#[test]
fn iso_parsing_is_strict() {
    assert_eq!(Ymd::parse_iso(b"1990-05-17"), Some(ymd(19900517)));
    for bad in
        [&b"1990-5-17"[..], b"1990/05/17", b"199a-05-17", b" 1990-05-17", b"1990-05-17 ", b"1990-13-01", b"+990-05-17"]
    {
        assert!(Ymd::parse_iso(bad).is_none(), "{}", String::from_utf8_lossy(bad));
    }
}

#[test]
fn leap_years() {
    assert!(is_leap_year(2000) && is_leap_year(2024) && is_leap_year(2400));
    assert!(!is_leap_year(1900) && !is_leap_year(2023) && !is_leap_year(2100));
}

fn spec(count: u16, bits: u16) -> ScalarsSpec {
    ScalarsSpec { type_id: TYPE_DATE.into(), count, bits, blind: false }
}

#[test]
fn handler_accepts_real_dates_only() {
    let h = DateHandler;
    for ok in ["1900-01-01", "1990-05-17", "2000-02-29", "2024-02-29", "2252-05-04"] {
        let v = h.encode(&spec(1, 17), ok.as_bytes()).unwrap();
        assert_eq!(v.len(), 1, "{ok}");
    }
    for bad in ["1899-12-31", "1900-02-29", "2023-02-29", "2024-02-30", "1990-04-31", "1990-00-10", "2252-05-05"] {
        assert!(h.encode(&spec(1, 17), bad.as_bytes()).is_err(), "{bad}");
    }
    // the date must fit the attribute
    assert!(h.encode(&spec(1, 16), b"2076-03-02").is_ok());
    assert!(h.encode(&spec(1, 16), b"2076-03-03").is_err());
    // layout
    assert!(h.encode(&spec(2, 17), b"1990-05-17").is_err());
    assert!(h.encode(&spec(1, 15), b"1990-05-17").is_err());
    assert!(h.encode(&spec(1, 33), b"1990-05-17").is_err());
}

#[test]
fn params_encoding() {
    let p = DateRangeParams::between(19761019, 20081018);
    assert_eq!(p.encode(), [&[3u8][..], &19761019u32.to_be_bytes(), &20081018u32.to_be_bytes()].concat());
    assert_eq!(DateRangeParams::decode(&p.encode()).unwrap(), p);
    assert_eq!(DateRangeParams::le(20081018).encode(), [&[2u8][..], &20081018u32.to_be_bytes()].concat());
    assert_eq!(DateRangeParams::ge(20011019).encode(), [&[1u8][..], &20011019u32.to_be_bytes()].concat());
    let le = 20081018u32.to_be_bytes();
    let bad: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        [&[0u8][..], &le].concat(),
        [&[4u8][..], &le].concat(),
        [&[2u8][..], &le, &[0]].concat(),
        [&[3u8][..], &le].concat(),
        [&[2u8][..], &19001301u32.to_be_bytes()].concat(),
        [&[2u8][..], &18991231u32.to_be_bytes()].concat(),
        [&[2u8][..], &19000100u32.to_be_bytes()].concat(),
    ];
    for b in bad {
        assert!(DateRangeParams::decode(&b).is_err(), "{b:?}");
    }
}

#[test]
fn bounds_and_clamping() {
    assert_eq!(DateRangeParams::le(20081018).bounds(17).unwrap(), (0, 40_472));
    assert_eq!(DateRangeParams::ge(20011019).bounds(17).unwrap(), (37_869, (1 << 17) - 1));
    assert_eq!(DateRangeParams::le(99991231).bounds(17).unwrap(), (0, (1 << 17) - 1));
    assert_eq!(DateRangeParams::between(20011019, 20081018).bounds(17).unwrap(), (37_869, 40_472));
    // empty and single-value ranges
    assert!(DateRangeParams::between(20081018, 20081018).bounds(17).is_err());
    assert!(DateRangeParams::between(20081019, 20081018).bounds(17).is_err());
    assert!(DateRangeParams::le(19000101).bounds(17).is_err());
    assert!(DateRangeParams::ge(99990101).bounds(17).is_err());
}

#[test]
fn attribute_type_checks() {
    let ok = AttributeSpec::scalars("d", TYPE_DATE, 1, 17);
    let p = DateRangeParams::le(20081018).encode();
    assert!(cd_date_range::proof_len(&ok, &p).is_ok());
    for bad in [
        AttributeSpec::octets("d"),
        AttributeSpec::scalars("d", "uint", 1, 17),
        AttributeSpec::scalars("d", TYPE_DATE, 2, 17),
        AttributeSpec::scalars("d", TYPE_DATE, 1, 15),
        AttributeSpec::scalars("d", TYPE_DATE, 1, 33),
    ] {
        assert!(matches!(cd_date_range::proof_len(&bad, &p), Err(Error::Reject(_))), "{bad:?}");
    }
}

#[test]
fn bases_cover_exactly_the_range() {
    let mut ns: Vec<u64> = (1..=700).collect();
    ns.extend([1 << 15, (1 << 16) - 1, 1 << 16, (1 << 16) + 1, 40_472, 93_202, (1 << 32) - 1]);
    for n in ns {
        let b = Bases::new(n);
        assert_eq!(b.k(), 64 - n.leading_zeros() as usize);
        assert!(b.beta.iter().all(|&x| x >= 1));
        assert_eq!(b.beta.iter().sum::<u64>(), n, "largest combination is N");
        let vs: Vec<u64> = if n <= 700 { (0..=n).collect() } else { vec![0, 1, n / 2, n - 1, n] };
        for v in vs {
            let d = b.digits(v).unwrap();
            assert!(d.iter().all(|&x| x <= 1));
            assert_eq!(d.iter().zip(&b.beta).map(|(a, c)| a * c).sum::<u64>(), v);
        }
        assert!(b.digits(n + 1).is_none());
    }
}

fn rand_scalar() -> Scalar {
    let mut w = [0u8; 64];
    OsRng.fill_bytes(&mut w);
    Scalar::from_bytes_wide(&w)
}

#[test]
fn range_proof_round_trip() {
    let (y0, y1) = commitment_generators(SUITE, &SUITE.api_id()).unwrap();
    let ch = |ci: &ChallengeInput| -> bbs_cd_plugin::Result<Scalar> {
        let h = bbs_cd_plugin::transcript::Transcript::new(b"test").add(b"d", ci.d).add(b"a", ci.a).add(b"b", ci.b);
        let mut w = [0u8; 64];
        w[..32].copy_from_slice(&h.digest());
        Ok(Scalar::from_bytes_wide(&w))
    };
    for n in [1u64, 2, 3, 5, 6, 40_472, (1 << 16) - 1, 1 << 16] {
        let b = Bases::new(n);
        for v in [0, n / 3, n] {
            let s = rand_scalar();
            let st = Statement { c_prime: y0 * Scalar::from(v) + y1 * s };
            let p = range::prove(&st, &b, v, s, &ch, &mut OsRng).unwrap();
            assert_eq!(p.len(), range::proof_len(b.k()));
            range::verify(&st, &b, &p, &ch).unwrap();
            // the same proof does not verify for another committed value
            let other = Statement { c_prime: st.c_prime + y0 };
            assert!(range::verify(&other, &b, &p, &ch).is_err());
        }
        assert!(range::prove(&Statement { c_prime: y0 }, &b, n + 1, Scalar::zero(), &ch, &mut OsRng).is_err());
    }
}
