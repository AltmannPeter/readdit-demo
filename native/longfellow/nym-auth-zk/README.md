# nym-auth-zk

Longfellow zero-knowledge presentations of the **nym_auth mdoc attestation**
(`eu.europa.ec.eudi.nym_auth.1`, the rulebook's compact profile with `bsc` and `psc`):
the age range check on the committed birth date and the `known-offender-matching-ssc`
pseudonym, in **one proof**. Nothing is disclosed but the pseudonym.

The deliverable is two Longfellow circuits (LFC2, in a zstd LFA2 archive, as Google ships its
mdoc circuits) and a native Rust witness generator, proved and verified with Google's Longfellow
Rust runtime (`google/longfellow-zk` at `61a8a73`, Longfellow v1: Ligero + sumcheck).

This is the **unoptimized baseline**: no public midstate, no bit packing, no other optimization.

## The statement

Public: the issuer key Q, `proof_time`, the age range (as bounds E and C), `verifier_id`, the
session (the bytes the device key signs), and the pseudonym (the statement's output).
Private: the IssuerSigned credential, `secret_seed` (16 bytes), `birth_date` (10 bytes
`YYYY-MM-DD`), the device signature.

The proof shows:

1. The issuer signed the MSO under Q (ECDSA P-256 over the COSE Sig_structure, hashed in full
   from the SHA-256 initial value).
   - The Sig_structure's SHA-256 padding is checked in the circuit: its private length L, the 0x80
     byte at L, zeros after it, and the length field 8L. The same holds for the `bsc` item.
   - Every value the circuit reads from the Sig_structure or the item ends within L, so no read
     reaches the padding.
2. The MSO's docType is `eu.europa.ec.eudi.nym_auth.1`.
3. `validFrom <= proof_time <= validUntil`, both bounds included (the rulebook).
4. The device key in the MSO signed the session: ECDSA over e2 = SHA-256 of the detached
   COSE_Sign1 Sig_structure of DeviceAuthentication (empty DeviceNameSpaces, protected `{1: -7}`).
5. The MSO lists the digest of the `bsc` item, whose value is a 32-byte bstr.
6. `bsc = SHA-256(secret_seed || birth_date)`.
7. `E <= birth_date <= C`, compared on the full-date's digits. E and C come from the range and the
   UTC date of `proof_time`, as the rulebook defines them. A missing bound takes the widest value
   (0000-00-00, 9999-99-99).
8. `pseudonym = SHA-256("nym_auth/v1/known-offender-matching-ssc" || secret_seed || 0^32 ||
   verifier_input)`, with `verifier_input = SHA-256(verifier_id)`.

`psc` is signed but not read.

## Use

```rust
use nym_auth_zk::{AgeRange, Holder, Prover, Request, Session, Verifier};
use runtime_random::SecureRandomEngine;

let request = Request {
    issuer_key: (qx, qy),                                   // P-256, big-endian
    proof_time: "2026-10-27T12:00:00Z".into(),
    age_range: Some(AgeRange::parse("13-17")?),             // or None
    verifier_id: "x509_san_dns:rp.example.com".into(),
    session: Session::DcApi { origin, nonce, jwk_thumbprint },  // or Session::Redirect {..}
};

// Wallet, in two phases
let prover = Prover::load()?;
let holder = Holder { credential: &issuer_signed_cbor, secret_seed, birth_date: *b"2010-05-17" };
let pre = prover.prebuild(&request, &holder, &mut rng)?;      // during consent: checks, hash circuit committed
let to_sign = Prover::device_signed_bytes(&request);         // after the PIN, the device key signs this (ES256)
let presentation = prover.prove_prebuilt(pre, &device_signature_r_s, &mut rng)?;
// or in one call: prover.prove(&request, &holder, &device_signature_r_s, &mut rng)?

// Verifier: every public value comes from its own request, plus the presentation's pseudonym.
let verifier = Verifier::load()?;
verifier.verify(&request, &presentation)?;

// The registry's system_id: urn:circuits:sha256:<SHA-256 of circuits/nym_auth_mdoc_bsc.lfa2.zst>
assert_eq!(nym_auth_zk::system_id(), "urn:circuits:sha256:f4d75ee2a112c63adfb00f1da45347c4691085c8cca6ab13cee7b03f00cdbd52");
```

`Prover::load` and `Verifier::load` decompress the shipped archive and check each circuit against
its Longfellow id. Build them once and reuse them. A prover needs only `Prover` and a verifier
only `Verifier`.

`rng` is `runtime_random::SecureRandomEngine` (the OS CSPRNG).

`prebuild` does everything that needs no device signature:

- it parses the credential;
- it checks the holder's data against the request, and refuses with `Error::Holder(reason)` when
  the issuer signature, the opening of `bsc`, the validity at `proof_time` or the age range does
  not hold;
- it draws the MAC keys, builds the hash circuit's witness and commits it.

That is about a fifth of the proving time (§ Soundness and performance). `prove_prebuilt` checks
the device signature (`Error::Holder`), then commits the signature circuit, draws the MAC challenge
and proves both circuits. These steps must follow the signature: the challenge comes after both
commitments.

`proof_time` is fixed at `prebuild`, so finish within the verifier's tolerance. `Prebuilt` holds
the holder's secrets. It is `Send`, not `Clone`, and is consumed by `prove_prebuilt`.

## Files

| Path | What |
|---|---|
| `circuits/nym_auth_mdoc_bsc.lfa2.zst` | zstd LFA2 archive with entries `hash` and `sig` (what the code loads) |
| `circuits/hash.lfc2`, `circuits/sig.lfc2` | the same circuits as raw LFC2 |
| `circuits/hash.id`, `circuits/sig.id` | their Longfellow ids (`core_proto::circuit::compute_id`) |
| `src/mdoc.rs` | IssuerSigned parsing: the Sig_structure, the read positions, the `bsc` item |
| `src/request.rs` | proof_time, age range to E/C, verifier_input, session transcript, device-signed bytes |
| `src/witness.rs` | both circuits' public and private inputs, in input order |
| `src/sha.rs`, `src/ecdsa.rs`, `src/gf.rs`, `src/cbor.rs` | SHA-256 trace, ECDSA ladder witness, GF(2^128), CBOR |
| `src/zk.rs` | circuit loading; commit, challenge, prove and verify on Google's runtime |
| `tests/vectors.rs` | end to end on the rulebook's test vectors (`tests/data`) |
| `tests/synthetic.rs` | three more holders (`tests/data/synthetic`, TEST ONLY): a birthday edge, 29 February, no `psc` |
| `tests/two_phase.rs` | the two-phase prover, its refusals, `system_id` |
| `tests/golden.rs`, `tests/golden/` | fixed presentations every verifier must accept (written by `examples/golden.rs`) |
| `examples/bench.rs` | timings |

## The circuits

| | hash | sig |
|---|---:|---:|
| field | GF(2^128) | P-256 base field |
| Longfellow id | `a5856d5c…49f336ca` | `6a62a572…bc1e315f` |
| inputs (incl. the constant 1) | 78,301 | 5,275 |
| public inputs (incl. the constant 1) | 278 | 1,155 |
| subfield boundary | 78,289 | 5,275 |
| layers | 12 | 9 |
| LFC2 bytes | 1,453,829 | 83,610 |
| Ligero (rateinv, nreq, block_enc) | 7, 132, 5111 | 7, 132, 3959 |

The archive is 447,379 bytes. The circuits are fixed in size, to the rulebook's compact profile:

- a Sig_structure of 7 SHA-256 blocks (the vectors' 423 bytes);
- a `bsc` item of 2 blocks (108 bytes);
- the opening of 1 block;
- the pseudonym message of 2 blocks.

Within those blocks the lengths are private: the Sig_structure may be 376 to 439 bytes and the
item 56 to 119 bytes. A credential without `psc` (a 388-byte Sig_structure) uses the same circuits.
The prover refuses a credential of other block counts. Every holder of the profile gets the same
circuits, so the circuits leak nothing about the credential.

## Composition and proof format

This is Google's mdoc composition (`mdoc_zk` v7 `run_mdoc_prover` / `run_mdoc_verifier`), with
this statement's MAC relation:

1. Start the Fiat–Shamir transcript with `Transcript::new("nym_auth/v1/mdoc-bsc/longfellow" || e2)`.
2. Commit the hash circuit's private inputs (Ligero), then the signature circuit's, on that
   transcript.
3. Draw the MAC challenge `c = transcript.bytes(16)`, a little-endian GF(2^128) element.
4. Compute the MAC tags: `t_k = a_k + c · m_k` in GF(2^128), for k = 0..5. This is the affine MAC
   `ax + b` of Longfellow's specification: the verifier's challenge `c` is the multiplier, the
   prover's key `a_k` the offset. Google's implementation uses `(a_p + a_v) · m` instead. Trail of
   Bits' review flags that form (TOB-LIBZK-12): a zero word admits a forgery, and the tag shows
   whether the word is zero. The affine form has neither issue and needs no more witness.
   - `m` is the tied datum: e (the MSO's SHA-256 digest as a 32-byte integer), then the device
     key's x and y, each 32 bytes little-endian, in 16-byte words.
   - The `a_k` are fresh random keys. Both circuits commit them as private inputs, and each
     circuit checks the relation.
5. Prove the hash circuit, then the signature circuit. Each proof absorbs its circuit and public
   inputs (`write_sumcheck_statement`).

The proof bytes use Google's `MdocProof` layout: the six tags (16 bytes each, little-endian), the
hash circuit's `ZkProof`, then the signature circuit's `ZkProof`. A presentation is this plus the
32-byte pseudonym.

### Public inputs (after the constant 1)

**Hash circuit (277):**

- the docType pattern `67 "docType" 78 1c "eu.europa.ec.eudi.nym_auth.1"` (38 bytes), as:
  - 2 limbs of 16 bytes, each little-endian;
  - 6 tail elements, one per byte;
- `x^(now + 533333333333328)` and `x^(now + 533333333333329)`, where now = proof_time as
  YYYYMMDDhhmmss;
- verifier_input's 256 bits (bit j of byte d at position 8d + j);
- the pseudonym's two 16-byte halves, little-endian;
- `x^(E + 533333328)` and `x^(C + 533333328)`, where E and C are YYYYMMDD (E = 0 and C = 99999999
  when absent);
- c;
- the six tags.

Here x is the field generator (the element 2).

**Signature circuit (1,154):**

- Q's x and y;
- e2's 256 bits, least significant first;
- c's 128 bits;
- the tags' 6 × 128 bits.

The private input order is `witness::hash_private` and `witness::sig_private`:

- **Hash circuit:**
  - the opening's bits;
  - the Sig_structure's padded bits;
  - each block's chaining value, then each block's W16..63 and per-round e and a;
  - the credential's read windows and their offsets;
  - the validity differences;
  - the `bsc` item (its bits, the windows, its blocks, the offsets);
  - the opening and pseudonym blocks;
  - the age differences;
  - the tied words;
  - the MAC keys.
- **Signature circuit:**
  - the tied bits;
  - the MAC key bits;
  - for each ECDSA verification (issuer, then device): r's and m's bits, R's y and the table
    sums, the 256 ladder accumulators, and 1/x_Q².

### Session binding

`Session` follows the rulebook's test vectors:

- **Redirect:** `OpenID4VPHandover` over `[client_id, nonce, jwk_thumbprint, response_uri]`.
- **DC API:** `OpenID4VPDCAPIHandover` over `[origin, nonce, jwk_thumbprint]`.

The jwk_thumbprint is a bstr, or null.

## Soundness and performance

Each circuit is proved at Longfellow's parameters (inverse rate 7, 132 opened columns). By
Longfellow's interactive bound, the statement's error is about 2^-108.3: the hash proof about
2^-109.0, the signature proof about 2^-109.7, plus 6/2^128 for the MAC.

Single thread, cloud Xeon @ 2.1 GHz, `target-cpu=native` (copy `cargo-config.toml` to `.cargo/config.toml`):

| | |
|---|---:|
| circuit load (each side) | ~55–80 ms |
| prove (witness, commit, both proofs) | ~200–280 ms, of which `prebuild` ~40 ms |
| verify | ~100–140 ms |
| proof | ~323 KB (+ 32 B pseudonym) |

A generic x86-64 build, without the carry-less multiply, is about 5× slower.

## Tests

`cargo test --release` runs on the rulebook vectors (both credential variants, both channels):

- **Accepted:** the honest presentations prove and verify, and the pseudonym is the vectors' one.
- **Age cases:** the 7 cases hold or fail as the vectors say.
- **Refused by the verifier:**
  - a tampered proof or pseudonym;
  - another verifier_id, age range, proof_time, issuer key or session.
- **Refused by the prover** (`Error::Holder`, with the reason):
  - a wrong birth_date or secret_seed;
  - a wrong device signature;
  - a proof_time outside the validity;
  - an age outside the range;
  - another issuer key.
- **Validity bounds:** they are inclusive.
- **Unlinkability:** two presentations share no commitment.
- **Other holders** (`tests/synthetic.rs`): the age edges on a birthday and on 29 February, and a
  credential without `psc`.
- **Two phases** (`tests/two_phase.rs`): `prebuild` then `prove_prebuilt` verify, across threads;
  each phase refuses with its reason; `system_id` is the archive's SHA-256.
- **Golden presentations** (`tests/golden.rs`): the shipped proofs verify, and fail for any other
  verifier_id, proof_time, age range or pseudonym.
