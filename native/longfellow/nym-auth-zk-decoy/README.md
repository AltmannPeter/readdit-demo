# nym-auth-zk-decoy

Longfellow zero-knowledge presentations of the **nym_auth mdoc attestation**
(`eu.europa.ec.eudi.nym_auth.1`) under **nym_auth rulebook v0.6**, whose credential is the
**decoy-digest layout with the precomputed prefix**:
the age range check on the committed birth date and the `known-offender-matching-ssc`
pseudonym, in **one proof**. Nothing is disclosed but the pseudonym.

The deliverable is two Longfellow circuits (LFC2, in a zstd LFA2 archive, as Google ships its
mdoc circuits) and a native Rust witness generator. They are proved and verified with Google's
Longfellow ZK prover and verifier (`google/longfellow-zk` at `61a8a73`: Ligero and sumcheck),
with the prover's and verifier's independent work run in parallel on the caller's rayon pool
(`src/rt`). The output is byte for byte Google's at any thread count.

## The credential layout

The MSO's `valueDigests` hold the two commitments themselves:

- digestID 0: `bsc = SHA-256(secret_seed || birth_date)`;
- digestID 1: `psc = SHA-256(private_seed)`, or 32 zero bytes.

There are no IssuerSignedItems and no `nameSpaces`. The IssuerSigned is
`{ "issuerAuth": COSE_Sign1 }` with:

- protected header `a1 01 26`;
- unprotected header `{33: x5chain}`, one certificate as a bstr;
- payload `d8 18 59 01 8e` followed by the 398-byte MSO in a fixed key order;
- a 64-byte signature.

The COSE Sig_structure is therefore exactly 423 bytes, 7 SHA-256 blocks once padded. Every
private field sits at a fixed offset:

| Field | Offset | Bytes |
|---|---:|---:|
| `bsc` | 148 | 32 |
| `psc` | 183 | 32 |
| device key x | 248 | 32 |
| device key y | 283 | 32 |
| `signed` | 338 | 20 |
| `validFrom` | 370 | 20 |
| `validUntil` | 403 | 20 |

Every other byte is the template's (`mdoc::TEMPLATE`). `mdoc::parse` refuses any deviation before
proving.

The first 128 bytes, which hold the COSE head, the MSO's version, digestAlgorithm and docType, and
the head of valueDigests, are the same for every credential. The hash circuit starts SHA-256 at
their state H2 (`mdoc::PREFIX_STATE`), a constant of the circuit, and compresses blocks 2 to 6.

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
   over blocks 2 to 6. Every byte outside the seven fields is a constant of the circuit, so the
   docType, the key order, the CBOR heads and the padding are the template's.
2. `validFrom <= proof_time <= validUntil`, both bounds included, on the hashed bytes 370 and 403.
3. The device key at bytes 248 and 283 signed the session: ECDSA over e2 = SHA-256 of the detached
   COSE_Sign1 Sig_structure of DeviceAuthentication (empty DeviceNameSpaces, protected `{1: -7}`).
4. `bsc` (bytes 148–179, digestID 0) = `SHA-256(secret_seed || birth_date)`.
5. `E <= birth_date <= C`, compared on the full-date's digits. E and C come from the range and the
   UTC date of `proof_time`, as the rulebook defines them. A missing bound takes the widest value.
6. `pseudonym = SHA-256("nym_auth/v1/known-offender-matching-ssc" || secret_seed || 0^32 ||
   verifier_input)`, with `verifier_input = SHA-256(verifier_id)`.

Every check reads the same wires that are hashed: there are no copies, read windows or offsets.
`psc` and `signed` are hashed but not read.

## Use

```rust
use nym_auth_zk_decoy::{AgeRange, Holder, Prover, Request, Session, Verifier};
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

// The registry's system_id: urn:circuits:sha256:<SHA-256 of circuits/nym_auth_mdoc_decoy.lfa2.zst>
assert_eq!(nym_auth_zk_decoy::system_id(),
    "urn:circuits:sha256:5d7d2b5d094032df5b02f576d2ae7b99d3f0932d47516336693f8d670cfd63ac");
```

`Prover::load` and `Verifier::load` decompress the shipped archive and check each circuit against
its Longfellow id. Build each once and reuse it.

`prebuild` does everything that needs no device signature:

- it parses the credential against the layout;
- it checks the holder's data, and refuses with `Error::Holder(reason)` when the issuer signature,
  the opening of `bsc`, the validity at `proof_time` or the age range does not hold;
- it draws the MAC keys, builds the hash circuit's witness and commits it.

`prove_prebuilt` checks the device signature (`Error::Holder`). Then it commits the signature
circuit, draws the MAC challenge and proves both circuits. `proof_time` is fixed at `prebuild`.
`Prebuilt` holds the holder's secrets: it is `Send`, not `Clone`, and `prove_prebuilt` consumes
it.

### Threads

The prover and verifier use the rayon pool they run in: call them inside `pool.install(..)`.
`nym_auth_zk_decoy::threads()`, called inside the pool, gives its size.

| Feature | Effect |
|---|---|
| `parallel` (default) | the independent work runs in parallel |
| none (`--no-default-features`) | everything runs in order on the calling thread; same bytes |
| `reference` | Google's own `ZkProver` / `ZkVerifier`, for comparison; same bytes |

`examples/identity.rs` prints a digest of fixed presentations and the verdicts on tampered
copies. Its output is the same for every feature set and thread count (checked at 1, 2, 4 and 8
threads).

## Files

| Path | What |
|---|---|
| `circuits/nym_auth_mdoc_decoy.lfa2.zst` | zstd LFA2 archive, entries `hash` and `sig` (what the code loads) |
| `circuits/hash.lfc2`, `circuits/sig.lfc2` | the same circuits as raw LFC2 |
| `circuits/hash.id`, `circuits/sig.id` | their Longfellow ids (`core_proto::circuit::compute_id`) |
| `src/mdoc.rs` | the layout: the template, the fields, the prefix state, the strict parser |
| `src/request.rs` | proof_time, age range to E/C, verifier_input, session transcript, device-signed bytes |
| `src/witness.rs` | both circuits' public and private inputs, in input order; the 4-bit plucker packing |
| `src/sha.rs`, `src/ecdsa.rs`, `src/gf.rs`, `src/cbor.rs` | SHA-256 trace, ECDSA ladder witness, GF(2^128), CBOR |
| `src/zk.rs` | circuit loading; commit, challenge, prove and verify |
| `src/rt/` | Google's ZK prover and verifier with their independent work in parallel (Apache-2.0, see NOTICE) |
| `tests/vectors.rs` | end to end on the decoy test vectors (`tests/data/decoy_test_vectors*.json`) |
| `tests/synthetic.rs` | three more holders at their edges (`tests/data/decoy_synthetic_holders.json`, TEST ONLY) |
| `tests/two_phase.rs` | the two-phase prover, its refusals, `system_id` |
| `tests/golden.rs`, `tests/golden/` | fixed presentations every verifier must accept (written by `examples/golden.rs`) |
| `examples/bench.rs` | timings |
| `examples/identity.rs` | byte identity across builds and thread counts |

## The circuits

| | hash | sig |
|---|---:|---:|
| field | GF(2^128) | P-256 base field |
| Longfellow id | `b52fc806…6b67ff62` | `6a62a572…bc1e315f` |
| inputs (incl. the constant 1) | 13,917 | 5,275 |
| public inputs (incl. the constant 1) | 269 | 1,155 |
| subfield boundary | 13,905 | 5,275 |
| layers | 16 | 9 |
| LFC2 bytes | 775,636 | 83,610 |
| Ligero (rateinv, nreq, block_enc) | 7, 132, 2546 | 7, 132, 3959 |

The archive is 227,925 bytes. The signature circuit is the same circuit as in `nym-auth-zk`
(the compact profile's), byte for byte.

**The hash circuit** checks eight SHA-256 compressions:

- the Sig_structure's blocks 2 to 6, from H2;
- the opening's block;
- the pseudonym message's two blocks.

Each compression's trace (the state after, W16..W63, each round's e and a: 5,888 bits) is packed
four bits per input with Google's 4-bit bit plucker. A packed input is a point of GF(16): the
span of the first four elements of Longfellow's Cantor basis (`witness::PLUCKER_BASIS`). The
circuit range-checks each point (p^16 = p) and unpacks its bits as linear functions of p, p^2,
p^4 and p^8. The packed inputs are subfield inputs, below the subfield boundary.

## Composition and proof format

This is Google's mdoc composition (`mdoc_zk` v7), with this statement's MAC relation:

1. Start the Fiat–Shamir transcript with
   `Transcript::new("nym_auth/v1/mdoc-decoy/longfellow" || e2)`.
2. Commit the hash circuit's private inputs (Ligero), then the signature circuit's.
3. Draw the MAC challenge `c = transcript.bytes(16)`, a little-endian GF(2^128) element.
4. Compute the MAC tags: `t_k = a_k + c · m_k` in GF(2^128), for k = 0..5.
   - `m` is the tied datum: e (the Sig_structure's SHA-256 as a 32-byte integer), then the device
     key's x and y, each 32 bytes little-endian, in 16-byte words.
   - The `a_k` are fresh random keys, committed in both circuits.
5. Prove the hash circuit, then the signature circuit.

The proof bytes use Google's `MdocProof` layout: the six tags (16 bytes each, little-endian), the
hash circuit's `ZkProof`, then the signature circuit's `ZkProof`. A presentation is this plus the
32-byte pseudonym.

The transcript domain differs from `nym-auth-zk`'s (`"nym_auth/v1/mdoc-bsc/longfellow"`). With
different circuits and system_ids, a presentation for one never verifies under the other.

### Public inputs (after the constant 1)

**Hash circuit (268):**

- `x^(now + 533333333333328)`, where now = proof_time as YYYYMMDDhhmmss and x is the element 2;
- verifier_input's 256 bits (bit j of byte d at position 8d + j);
- the pseudonym's two 16-byte halves, little-endian;
- `x^(E + 533333328)` and `x^(C + 533333328)`, where E and C are YYYYMMDD (E = 0 and C = 99999999
  when absent);
- c;
- the six tags.

There is no docType input: the docType is part of the constant prefix.

**Signature circuit (1,154):** as `nym-auth-zk`:

- Q's x and y;
- e2's 256 bits, least significant first;
- c's 128 bits;
- the tags' 6 × 128 bits.

The private input order is `witness::hash_private` and `witness::sig_private`.

**Hash circuit:**

- the opening's bits;
- the 188 field bytes' bits;
- the validity differences (2 × 47 bits);
- the age differences (2 × 27 bits);
- the eight compressions' packed traces (8 × 1,472);
- the tied words;
- the MAC keys.

**Signature circuit:** as `nym-auth-zk`.

### Session binding

`Session` follows the rulebook's test vectors:

- **Redirect:** `OpenID4VPHandover` over `[client_id, nonce, jwk_thumbprint, response_uri]`.
- **DC API:** `OpenID4VPDCAPIHandover` over `[origin, nonce, jwk_thumbprint]`.

## Soundness and performance

Each circuit is proved at Longfellow's parameters (inverse rate 7, 132 opened columns). By
Longfellow's interactive bound, the statement's error is at most about 2^-108.3, the same floor as
`nym-auth-zk`.

Measured on one core of a cloud Xeon, `target-cpu=native`, on Google's own prover path
(`reference`), against `nym-auth-zk` 0.2.0 on the same machine:

| | change |
|---|---:|
| prove | −31% |
| of which `prebuild` (before the PIN) | −76% |
| verify | −22% |
| peak memory | −45% |
| proof | −10.5% (about 289 KB, + 32 B pseudonym) |

Absolute times differ per machine; run `examples/bench.rs`. After the PIN, the signature circuit
now dominates: `prebuild` is under a tenth of the proving time.

## Tests

`cargo test --release` (12 tests):

- **Vectors** (the rulebook's keys, openings and sessions; the credential in the decoy layout):
  - both channels and both `psc` variants prove and verify;
  - the 7 age cases hold or fail;
  - tampered proofs and every changed request value are refused;
  - the prover's refusals carry their reasons.
- **Synthetic holders at their edges:** validity of one second, validFrom and validUntil
  inclusive, birth date at E and at C, 29 February, a zero `psc`.
- **Two phases**, `system_id`, and the **golden presentations**.
