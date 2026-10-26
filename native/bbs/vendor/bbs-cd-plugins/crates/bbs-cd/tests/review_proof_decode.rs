use bbs_cd::utils::octets_to_proof;

#[test]
fn arbitrary_proof_bytes_do_not_panic_decoder() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for len in 0..2048 {
        let mut data = vec![0u8; len];
        for b in &mut data {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *b = state as u8;
        }
        let result = std::panic::catch_unwind(|| octets_to_proof(&data));
        assert!(result.is_ok(), "proof decoder panicked at length {len}");
    }
}
