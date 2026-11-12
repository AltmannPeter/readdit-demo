# Test credentials (TEST ONLY)

nym_auth **rulebook v0.7** mdoc credentials (INTEGRATION.md §5). They are signed with the rulebook
v0.5 test vectors' **TEST** Document Signer key (`keys.document_signer` in
`nym_auth_v07_test_vectors.json`). Holders A to D use the vectors' device key (`keys.device`);
holder E has its own TEST device key, with an odd y. Never trust these keys outside tests.

| Holder | secret_seed | birth_date | psc | validity | What it exercises |
|---|---|---|---|---|---|
| A | the vectors' | 2010-05-17 | from the vectors' private_seed | 2026-10-27T00:00:00Z – 2027-10-27T00:00:00Z | the vectors' holder (e `cd3fe43b…174edd7e`) |
| A0 | the vectors' | 2010-05-17 | 32 zero bytes | as A | no private seed |
| B | 20..2f | 2008-10-28 | from 40..4f | 2026-10-27T12:00:00Z – the same second | validity of one second; birth == E of 13-17 on 2026-10-27 |
| C | 50..5f | 2000-02-29 | from 60..6f | 2020-01-01T00:00:00Z – 2099-12-31T23:59:59Z | 29 February |
| D | ff × 16 | 2013-10-27 | 32 zero bytes | 2026-10-26T23:59:59Z – 2026-10-27T12:00:00Z | birth == C of 13-17 on 2026-10-27; validUntil == proof_time |
| E | 70..7f | 1990-01-01 | from 80..8f | as A | a device key with odd y: `-3` is true (`f5`) |

`psc` "from s" is `AES-128(s, "nym/p" ‖ 01 ‖ 0^10) ‖ AES-128(s, "nym/p" ‖ 02 ‖ 0^10)`.

- `v07_<holder>.cbor` is the IssuerSigned CBOR.
- `holders.json` holds each holder's seed, birth date, `bsc`, `psc`, validity, device key (x, y,
  sign; E's private key as `device_d`), Sig_structure, e, and the `aes-128` pseudonym for
  `verifier_id` `x509_san_dns:rp.example.com`.
- `nym_auth_v07_test_vectors.json` is the crate's `tests/data/v07_test_vectors.json`: the keys,
  openings and sessions, holder A's credential, its DeviceResponses, H and the pseudonym.
- `issue_v07.py` issued them: `python3 issue_v07.py nym_auth_v07_test_vectors.json OUT_DIR`.
  The ECDSA signatures are randomized, so each run gives new bytes in the same layout; every other
  value in `holders.json` comes out the same.

`nym-auth-zk-v07/tests/data/` holds the same credentials: A and A0 in `v07_test_vectors*.json`,
and B to E in `v07_synthetic_holders.json`.
