# Test credentials (TEST ONLY)

nym_auth **rulebook v0.6** mdoc credentials, in the decoy-digest layout (INTEGRATION.md §5). They
are signed with the rulebook v0.5 test vectors' **TEST** Document Signer key (`nym_auth_test_vectors.json`, `keys.document_signer`).
They use the vectors' device key (`keys.device`). Never trust these keys outside tests.

| Holder | secret_seed | birth_date | psc | validity | What it exercises |
|---|---|---|---|---|---|
| A | the vectors' | 2010-05-17 | SHA-256(the vectors' private_seed) | 2026-10-27T00:00:00Z – 2027-10-27T00:00:00Z | the vectors' holder (its e is the guide's check value `8c09a012…0928535c`) |
| A0 | the vectors' | 2010-05-17 | 32 zero bytes | as A | no private seed |
| B | 20..2f | 2008-10-28 | SHA-256(40..4f) | 2026-10-27T12:00:00Z – the same second | validity of one second; birth == E of 13-17 on 2026-10-27 |
| C | 50..5f | 2000-02-29 | SHA-256(60..6f) | 2020-01-01T00:00:00Z – 2099-12-31T23:59:59Z | 29 February |
| D | ff × 16 | 2013-10-27 | 32 zero bytes | 2026-10-26T23:59:59Z – 2026-10-27T12:00:00Z | birth == C of 13-17 on 2026-10-27; validUntil == proof_time |

- `decoy_<holder>.cbor` is the IssuerSigned CBOR.
- `holders.json` holds each holder's seed, birth date, `bsc`, `psc`, validity, Sig_structure and e.
- `issue_decoy.py` issued them: `python3 issue_decoy.py nym_auth_test_vectors.json OUT_DIR`.
  The ECDSA signatures are randomized, so each run gives new bytes in the same layout.

`nym-auth-zk-decoy/tests/data/` holds the same credentials: A and A0 in `decoy_test_vectors*.json`,
and B, C and D in `decoy_synthetic_holders.json`.
