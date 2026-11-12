# Changes

## 0.3.0 (2026-10-28)

Speed only. The circuits (`circuits/nym_auth_mdoc_bsc.lfa2.zst`), the system_id, the transcript,
the order of the commitments, challenges and proofs, the random draws, and the proof bytes for
the same random engine are those of 0.2.0. Every verdict is the same, and so is the public API.

- The commitments, proofs and verifications run on `src/rt`: Google's ZK prover and verifier
  (longfellow-zk 61a8a73) with their independent work at once on the rayon pool the caller runs
  in. The tableau's rows, the Merkle leaves, the dot product, the circuit's evaluation, the
  sumcheck rounds' sums and the verifier's bound quads are split; the rounds stay in order.
- Feature `parallel` (default): rayon. Without it, everything runs in order on the calling thread
  and gives the same bytes.
- Feature `reference`: Google's `ZkProver` and `ZkVerifier` themselves, 0.2.0's path, for
  comparing against.
- `threads()`: the thread count proving and verifying run on (the current rayon pool's, or 1).
- `examples/gates.rs`: proves with a deterministic random engine (test only) and prints each
  proof's digest, and every verifier verdict on the proofs and the golden presentations, so that
  builds can be compared: the default build at 1, 2, 4 and 8 threads, `--no-default-features` and
  `--features reference` print the same.
- `examples/bench.rs` prints the thread count, the medians and the peak RSS.
- Two clippy fixes in `request.rs` and `zk.rs` (no change in behaviour).
