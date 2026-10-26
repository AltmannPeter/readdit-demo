# Source of the BBS vectors

These frozen vectors were extracted from the draft text; do not edit by hand.

- File: `fixtures/bbs/source/draft-irtf-cfrg-bbs-signatures-13.txt`
- SHA-256: `78b71f9a4bcdf57fbce694b015ed22bcf5b71ff5263b8f8d57ae2bbcf6514cd2`
- Sections: 8.1–8.4.5 (8.3 = BLS12-381-SHAKE-256, 8.4 = BLS12-381-SHA-256), D.1.1–D.1.3 and D.2.1–D.2.3.
- The draft's Appendix G records no cryptographic changes in -12 or -13, so these vectors
  apply to the BBS-12 baseline pinned by the spec.

Scalars are 32-octet big-endian hex. Messages are listed in order of appearance;
`messageRefs8_2` gives each message's zero-based position in Section 8.2, matched by value.

## Known defects in the draft text

- D.2.2.1 (BLS12-381-SHA-256, No Header Valid Proof) lists `T = h''` and a `challenge`
  instead of `T1` and `T2`. The fixture records the challenge and leaves T1/T2 null;
  domain and the A_bar, B_bar, D prefix of the proof are still checked.
- The D.x.2.x proof fixtures do not list their random scalars; they are
  regenerated from the 8.x.5 SEED and DST with `seeded_random_scalars` (draft 8.1).
