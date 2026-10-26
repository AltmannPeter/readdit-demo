use cd_date_range::range::Bases;
use cd_date_range::DateRangeParams;

#[test]
fn arbitrary_date_params_do_not_panic_decoder() {
    let mut state = 0xa5a5_1234_789a_bcdeu64;
    for len in 0..64 {
        for _ in 0..128 {
            let mut data = vec![0u8; len];
            for b in &mut data {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *b = state as u8;
            }
            let result = std::panic::catch_unwind(|| DateRangeParams::decode(&data));
            assert!(result.is_ok(), "date params decoder panicked at length {len}");
        }
    }
}

#[test]
fn arbitrary_limit_bases_cover_the_interval_without_overflow() {
    let limits =
        (1u64..=4096).chain([65_535u64, 65_536, 65_537, (1 << 31) - 1, 1 << 31, (1 << 31) + 1, u32::MAX as u64]);
    for n in limits {
        let bases = Bases::new(n);
        assert_eq!(bases.beta.iter().sum::<u64>(), n);
        for v in [0, 1, n / 3, n / 2, n.saturating_sub(1), n] {
            let digits = bases.digits(v).unwrap();
            assert!(digits.iter().all(|d| *d <= 1));
            assert_eq!(digits.iter().zip(&bases.beta).map(|(d, b)| d * b).sum::<u64>(), v);
        }
        assert!(bases.digits(n + 1).is_none());
    }
}
