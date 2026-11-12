# nym-auth-zk-v07

Longfellow zero-knowledge presentations of the **nym_auth mdoc attestation**
(`eu.europa.ec.eudi.nym_auth.1`) under **rulebook v0.7**: the age range check on the committed
birth date and the `known-offender-matching-ssc` pseudonym with `prf` `aes-128`, in **one proof**.
Nothing is disclosed but the pseudonym.

The deliverable is two Longfellow circuits (LFC2, in a zstd LFA2 archive, as Google ships its
mdoc circuits) and a native Rust witness generator. They are proved and verified with Google's
Longfellow ZK prover and verifier (`google/longfellow-zk` at `61a8a73`: Ligero and sumcheck),
with the prover's and verifier's independent work run in parallel on the caller's rayon pool
(`src/rt`). The output is byte for byte Google's at any thread count.

## What changed from v0.6

| | v0.6 (`nym-auth-zk-decoy`) | v0.7 (this crate) |
|---|---|---|
| valueDigests namespace | `eu.europa.ec.eudi.nym_auth.1` | `eu.nym_auth.v1` |
| device key in the MSO | x and y (`-3` a 32-byte bstr) | x and its sign (`-3` a bool, ISO 18013-5 9.1.2.4 / 9.1.5.2) |
| `bsc` | `SHA-256(secret_seed ‖ birth_date)` | two AES-128 blocks under `secret_seed` |
| `psc` | `SHA-256(private_seed)` | two AES-128 blocks under `private_seed` |
| pseudonym | SHA-256 in the circuit | AES-128 under `secret_seed` of H, which the verifier computes |
| MSO / Sig_structure | 398 / 423 bytes, 7 blocks | 350 / 375 bytes, 6 blocks |
| hash circuit | 8 SHA-256 compressions | 4 SHA-256 compressions + 680 AES S-boxes |
| MAC between the circuits | 6 words (e, x, y) | 4 words (e, x) |

## The credential layout

The MSO's `valueDigests`, under the namespace `eu.nym_auth.v1`, hold the two commitments
themselves:

- digestID 0: `bsc = AES-128(secret_seed, "nym/b" ‖ 01 ‖ birth_date) ‖ AES-128(secret_seed, "nym/b" ‖ 02 ‖ 0^10)`;
- digestID 1: `psc = AES-128(private_seed, "nym/p" ‖ 01 ‖ 0^10) ‖ AES-128(private_seed, "nym/p" ‖ 02 ‖ 0^10)`,
  or 32 zero bytes.

`secret_seed` (16 bytes) is sampled by the issuer; `birth_date` is the 10 characters
`YYYY-MM-DD`. The second block of `bsc` encrypts a constant: it commits to the key, since AES alone
is not key-committing.

The device key is a COSE_Key `{1: 2, -1: 1, -2: x, -3: sign}` with `sign` true when y is odd.

There are no IssuerSignedItems and no `nameSpaces`. The IssuerSigned is
`{ "issuerAuth": COSE_Sign1 }` with:

- protected header `a1 01 26`;
- unprotected header `{33: x5chain}`, one certificate as a bstr;
- payload `d8 18 59 01 5e` followed by the 350-byte MSO in a fixed key order;
- a 64-byte signature.

The COSE Sig_structure is therefore exactly 375 bytes, 6 SHA-256 blocks once padded. Every
private field sits at a fixed offset:

| Field | Offset | Bytes |
|---|---:|---:|
| `bsc` | 133 | 32 |
| `psc` | 168 | 32 |
| device key x | 233 | 32 |
| device key sign (`f4` / `f5`) | 266 | 1 |
| `signed` | 290 | 20 |
| `validFrom` | 322 | 20 |
| `validUntil` | 355 | 20 |

Every other byte is the template's (`mdoc::TEMPLATE`). `mdoc::parse` refuses any deviation before
proving, and decompresses y from x and the sign (`mdoc::decompress`).

The first 128 bytes hold the COSE head, the MSO's version, digestAlgorithm and docType, and the
head of valueDigests. They are the same for every credential. The hash circuit starts SHA-256 at
their state H2 (`mdoc::PREFIX_STATE`), a constant of the circuit, and compresses blocks 2 to 5.

## The statement

**Public:**

- the issuer key Q;
- `proof_time`;
- the age range, as bounds E and C;
- `verifier_id`;
- the session (the bytes the device key signs);
- the pseudonym (the statement's output).

**Private:**

- the IssuerSigned credential;
- `secret_seed` (16 bytes);
- `birth_date` (10 bytes, `YYYY-MM-DD`);
- the device signature.

The proof shows:

1. The issuer signed the Sig_structure under Q (ECDSA P-256). Its SHA-256 is computed from H2
   over blocks 2 to 5. Every byte outside the seven fields is a constant of the circuit, so the
   docType, the namespace, the key order, the CBOR heads and the padding are the template's.
2. `validFrom <= proof_time <= validUntil`, both bounds included, on the hashed bytes 322 and 355.
3. A device key with the hashed x at byte 233 signed the session: ECDSA over e2 = SHA-256 of the
   detached COSE_Sign1 Sig_structure of DeviceAuthentication (empty DeviceNameSpaces, protected
   `{1: -7}`). The circuit takes y as a private input on the curve; it does not read the sign
   byte. Only the holder of the device key can sign, and both points with that x are the holder's
   key or its negation, so this binds the same key (see INTEGRATION.md §4).
4. `bsc` (bytes 133–164, digestID 0) is the two AES-128 blocks above, under the private
   `secret_seed`, of the private `birth_date`.
5. `E <= birth_date <= C`, compared on the full-date's digits. E and C come from the range and the
   UTC date of `proof_time`, as the rulebook defines them. A missing bound takes the widest value.
6. `pseudonym = AES-128(secret_seed, H[0..16]) ‖ AES-128(secret_seed, H[16..32])`, with
   `H = SHA-256("nym_auth/v1/aes-128/known-offender-matching-ssc" ‖ 0^32 ‖ verifier_input)` and
   `verifier_input = SHA-256(verifier_id)`. H is a public input: the verifier computes it.

Every check reads the same wires that are hashed: there are no copies, read windows or offsets.
The AES key schedule is computed once and used by all four encryptions. `psc` and `signed` are
hashed but not read.

## Use

```rust
use nym_auth_zk_v07::{AgeRange, Holder, Prover, Request, Session, Verifier};
use runtime_random::SecureRandomEngine;

let request = Request {
    issuer_key: (qx, qy),                                   // P-256, big-endian
    proof_time: "2026-10-27T12:00:00Z".into(),
    age_range: Some(AgeRange::parse("13-17")?),             // or None
    verifier_id: "x509_san_dns:rp.example.com".into(),
    session: Session::DcApi { origin, nonce, jwk_thumbprint },  // or Session::Redirect {..}
};

// Wallet, in two phases, inside the app's rayon pool
let prover = Prover::load()?;
let holder = Holder { credential: &issuer_signed_cbor, secret_seed, birth_date: *b"2010-05-17" };
let pre = pool.install(|| prover.prebuild(&request, &holder, &mut SecureRandomEngine::new()))?;
let to_sign = Prover::device_signed_bytes(&request);   // after the PIN, the device key signs this (ES256)
let presentation = pool.install(|| prover.prove_prebuilt(pre, &device_signature_r_s, &mut SecureRandomEngine::new()))?;

// Verifier: every public value comes from its own request, plus the presentation's pseudonym.
let verifier = Verifier::load()?;
verifier.verify(&request, &presentation)?;

// The registry's system_id: urn:circuits:sha256:<SHA-256 of circuits/nym_auth_mdoc_v07.lfa2.zst>
assert_eq!(nym_auth_zk_v07::system_id(),
    "urn:circuits:sha256:218a72dea317cfcde2e715860e6b3a5dda2c67260f4cf9e8311c62ef900c34bd");
```

`Prover::load` and `Verifier::load` decompress the shipped archive and check each circuit against
its Longfellow id. Build each once and reuse it.

`prebuild` does everything that needs no device signature:

- it parses the credential against the layout and decompresses the device key;
- it checks the holder's data, and refuses with `Error::Holder(reason)` when the issuer signature,
  the opening of `bsc`, the validity at `proof_time` or the age range does not hold;
- it draws the MAC keys, builds the hash circuit's witness (with the AES trace) and commits it.

`prove_prebuilt` checks the device signature (`Error::Holder`). Then it commits the signature
circuit, draws the MAC challenge and proves both circuits. `proof_time` is fixed at `prebuild`.
`Prebuilt` holds the holder's secrets: it is `Send`, not `Clone`, and `prove_prebuilt` consumes
it.

`aes::bsc`, `aes::psc` and `witness::pseudonym` compute the commitments and the pseudonym off
circuit (constant-time AES-128, no table lookups on secrets), for issuers and tests.

### Threads

The prover and verifier use the rayon pool they run in: call them inside `pool.install(..)`.
`nym_auth_zk_v07::threads()`, called inside the pool, gives its size.

| Feature | Effect |
|---|---|
| `parallel` (default) | the independent work runs in parallel |
| none (`--no-default-features`) | everything runs in order on the calling thread; same bytes |
| `reference` | Google's own `ZkProver` / `ZkVerifier`, for comparison; same bytes |
| `aes-ctr-rng` | `rng::AesCtrEngine`, an AES-256-CTR generator keyed once from the OS, for benchmarks (off by default) |

`examples/identity.rs` prints a digest of fixed presentations and the verdicts on tampered
copies. Its output is the same for every feature set and thread count (checked at 1, 2, 4 and 8
threads).

The prover stores the rows of its Ligero table whose messages lie in GF(2^16) as 2-byte
encodings (`src/rt/ligero.rs`, `Row::Packed`), as Google's C++ prover does: about 90 of the hash
table's rows. The proof bytes are unchanged.

## Files

| Path | What |
|---|---|
| `circuits/nym_auth_mdoc_v07.lfa2.zst` | zstd LFA2 archive, entries `hash` and `sig` (what the code loads) |
| `circuits/hash.lfc2`, `circuits/sig.lfc2` | the same circuits as raw LFC2 |
| `circuits/hash.id`, `circuits/sig.id` | their Longfellow ids (`core_proto::circuit::compute_id`) |
| `src/mdoc.rs` | the layout: the template, the fields, the prefix state, the strict parser, decompression |
| `src/aes.rs` | AES-128 (FIPS 197) with the S-box trace; `bsc`, `psc`, the pseudonym |
| `src/request.rs` | proof_time, age range to E/C, verifier_input, session transcript, device-signed bytes |
| `src/witness.rs` | both circuits' public and private inputs, in input order; the 4-bit plucker packing |
| `src/sha.rs`, `src/ecdsa.rs`, `src/gf.rs`, `src/cbor.rs` | SHA-256 trace, ECDSA ladder witness, GF(2^128), CBOR |
| `src/zk.rs` | circuit loading; commit, challenge, prove and verify |
| `src/rt/` | Google's ZK prover and verifier with their independent work in parallel (Apache-2.0, see NOTICE) |
| `src/rng.rs` | the AES-CTR benchmark generator (feature `aes-ctr-rng`) |
| `tests/vectors.rs` | end to end on the v0.7 test vectors (`tests/data/v07_test_vectors*.json`) |
| `tests/synthetic.rs` | four more holders at their edges (`tests/data/v07_synthetic_holders.json`, TEST ONLY) |
| `tests/two_phase.rs` | the two-phase prover, its refusals, `system_id` |
| `tests/golden.rs`, `tests/golden/` | fixed presentations every verifier must accept (written by `examples/golden.rs`) |
| `examples/bench.rs` | timings |
| `examples/identity.rs` | byte identity across builds and thread counts |

## The circuits

| | hash | sig |
|---|---:|---:|
| field | GF(2^128) | P-256 base field |
| Longfellow id | `18d504fe…7ee0b073` | `55cd9b6e…7f11a344` |
| inputs (incl. the constant 1) | 9,183 | 4,508 |
| public inputs (incl. the constant 1) | 267 | 899 |
| subfield boundary | 9,175 | 4,508 |
| layers | 16 | 9 |
| LFC2 bytes | 489,438 | 74,805 |
| Ligero (rateinv, nreq, block_enc) | 7, 132, 2555 | 7, 132, 4031 |

The archive is 152,142 bytes.

**The hash circuit** checks four SHA-256 compressions (the Sig_structure's blocks 2 to 5, from
H2) and AES-128: one key schedule (40 S-boxes) and four encryptions (640 S-boxes), the two blocks
of `bsc` and the two of the pseudonym.

- Each compression's trace (the state after, W16..W63, each round's e and a: 5,888 bits) is
  packed four bits per input with Google's 4-bit bit plucker. A packed input is a point of GF(16):
  the span of the first four elements of Longfellow's Cantor basis (`witness::PLUCKER_BASIS`). The
  circuit range-checks each point (p^16 = p) and unpacks its bits as linear functions of p, p^2,
  p^4 and p^8.
- **AES.** The AES state lives on bit wires; every linear step (ShiftRows, MixColumns,
  AddRoundKey, the S-box's affine map, the key schedule's XORs) is GF(2)-linear on them. For each
  S-box, the prover supplies v, the inverse of its input u in AES's GF(2^8) (0 for 0), as 8 bits
  of the AES trace. The circuit maps u and v into GF(2^128) by the field embedding
  φ(b) = Σ b_j g^j, with g a root of t^8 + t^4 + t^3 + t + 1 in Longfellow's field, and checks
  `x·y·x = x` and `x·y·y = y` for x = φ(u), y = φ(v). These two equations admit exactly v = u^-1
  (and v = 0 for u = 0): checked exhaustively over all 65,536 pairs. The trace (704 bytes:
  680 inverses and 24 zero bytes) is packed four bits per input as the SHA-256 traces.

The packed inputs are subfield inputs, below the subfield boundary.

**The signature circuit** verifies the issuer's ECDSA signature over e and the device key's over
e2. The device key's y is a private input (one field element), checked on the curve by the
verification itself; its x comes from the tied bits.

## Composition and proof format

This is Google's mdoc composition (`mdoc_zk` v7), with this statement's MAC relation:

1. Start the Fiat–Shamir transcript with
   `Transcript::new("nym_auth/v1/mdoc-v07/longfellow" ‖ e2)`.
2. Commit the hash circuit's private inputs (Ligero), then the signature circuit's.
3. Draw the MAC challenge `c = transcript.bytes(16)`, a little-endian GF(2^128) element.
4. Compute the MAC tags: `t_k = a_k + c · m_k` in GF(2^128), for k = 0..3.
   - `m` is the tied datum: e (the Sig_structure's SHA-256 as a 32-byte integer), then the device
     key's x, each 32 bytes little-endian, in 16-byte words.
   - The `a_k` are fresh random keys, committed in both circuits.
5. Prove the hash circuit, then the signature circuit.

The proof bytes use Google's `MdocProof` layout: the four tags (16 bytes each, little-endian), the
hash circuit's `ZkProof`, then the signature circuit's `ZkProof`. A presentation is this plus the
32-byte pseudonym.

The transcript domain differs from v0.6's (`"nym_auth/v1/mdoc-decoy/longfellow"`) and v0.5's
(`"nym_auth/v1/mdoc-bsc/longfellow"`). With different circuits and system_ids, a presentation for
one never verifies under another.

### Public inputs (after the constant 1)

**Hash circuit (266):**

- `x^(now + 533333333333328)`, where now = proof_time as YYYYMMDDhhmmss and x is the element 2;
- H's 256 bits (bit j of byte d at position 8d + j);
- the pseudonym's two 16-byte halves, little-endian;
- `x^(E + 533333328)` and `x^(C + 533333328)`, where E and C are YYYYMMDD (E = 0 and C = 99999999
  when absent);
- c;
- the four tags.

**Signature circuit (898):**

- Q's x and y;
- e2's 256 bits, least significant first;
- c's 128 bits;
- the tags' 4 × 128 bits.

The private input order is `witness::hash_private` and `witness::sig_private`.

**Hash circuit:**

- the opening's bits (`secret_seed` ‖ `birth_date`, 208);
- the 157 field bytes' bits;
- the validity differences (2 × 47 bits);
- the age differences (2 × 27 bits);
- the four compressions' packed traces (4 × 1,472);
- the packed AES trace (1,408);
- the tied words (4);
- the MAC keys (4).

**Signature circuit:**

- the tied bits (e, x: 512);
- the MAC keys' bits (512);
- the device key's y (1);
- the two ECDSA verifications' advice.

### Session binding

`Session` follows the rulebook's test vectors:

- **Redirect:** `OpenID4VPHandover` over `[client_id, nonce, jwk_thumbprint, response_uri]`.
- **DC API:** `OpenID4VPDCAPIHandover` over `[origin, nonce, jwk_thumbprint]`.

## Soundness and performance

Each circuit is proved at Longfellow's parameters (inverse rate 7, 132 opened columns). By
Longfellow's interactive bound, the statement's error is at most about 2^-108.3, the same floor as
v0.5 and v0.6.

Measured on one core of a cloud Xeon (x86-64, `target-cpu=native`), medians of 75 presentations,
against `nym-auth-zk-decoy` 0.1.0 (v0.6) on the same machine and the same prover path:

| | threaded runtime (default) | Google's path (`reference`) |
|---|---:|---:|
| prove | −21% | −22% |
| of which `prebuild` (before the PIN) | −20% | −30% |
| of which after the PIN | −21% | −21% |
| verify | −24% | −21% |
| peak memory (process) | −31% | −26% |
| proof | −5.7% (about 273 KB, + 32 B pseudonym) | same bytes |

Absolute times differ per machine; run `examples/bench.rs`. After the PIN, the signature circuit
dominates. With `aes-ctr-rng`, `prebuild` falls a further 38% on this machine; the time after the
PIN does not change measurably.

## Tests

`cargo test --release` (15 tests):

- **AES:** FIPS 197 Appendix C.1, the S-box and inverse for every byte, the trace layout.
- **Vectors** (the rulebook's keys, openings and sessions; the credential in the v0.7 layout):
  - both channels and both `psc` variants prove and verify;
  - the 7 age cases hold or fail;
  - tampered proofs and every changed request value are refused;
  - the prover's refusals carry their reasons.
- **Synthetic holders at their edges:** validity of one second, validFrom and validUntil
  inclusive, birth date at E and at C, 29 February, a zero `psc`, a device key with odd y; each
  pseudonym checked against an independent AES-128 (the `aes` crate).
- **Two phases**, `system_id`, and the **golden presentations**.
