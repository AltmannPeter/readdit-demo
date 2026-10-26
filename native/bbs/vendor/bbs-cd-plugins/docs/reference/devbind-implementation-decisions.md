# Implementation decisions — DEVBIND-BBS-TOM-ECDSA/0.1

Running log of the choices made while building the research prototype of the
precomputed blinded-key BBS device-binding proposal. Each entry says whether it
is an **engineering choice** (no security argument needed beyond correctness),
a **provisional protocol choice** (affects the specification and must be
covered by the analysis), or an **assumption** (taken as given, not proved).
Status markers: *open* items need a decision or argument outside this
prototype.

Scope reminder: no direct ECDSA verification inside Tom-256, no Vega or
circuit-based proof system.

## A. Trust and issuance

**D-1 (assumption, supplied by Peter on 2026-10-15).** The issuer is trusted to
issue a correctly formed credential and to perform all required checks on the
device public key it signs: that Q is a valid non-identity P-256 point with
x, y < p, that its limbs are encoded as specified, and that the key's
hardware-binding attestation satisfies policy. The prototype implements these
checks in `Issuer.issue` (decode with on-curve check, coordinate bound,
attestation verification), but the security analysis treats them as an
assumption about the issuer, not as something the presentation proves.
Consequence: no blind issuance and no issuance-time proofs about Q are needed.

**D-2 (engineering).** The hardware attestation is simulated: a
`Manufacturer` Ed25519 key signs the device public key with the
policy label `software-device-simulation`. This stands in for platform
attestation. It has no security role in the prototype beyond letting the
issuer apply a policy check.

**D-3 (provisional protocol).** The credential header (BBS `header`) is
a fixed, per-profile encoding (`credential_header`) of protocol id, L, limb
indexes, limb width and encodings. It is identical for all holders of the
same issuer and attribute count, so it is not a linkable identifier.

## B. BBS layer

**D-4 (provisional protocol, experimental interface).** The device key is signed as four
**numeric** BBS scalars at message indexes 0..3: x0, x1, y0, y1 with
x = x0 + 2^128·x1 and y = y0 + 2^128·y1, each limb in [0, 2^128). The
remaining attributes are mapped with the standard `MAP_MSG_TO_SCALAR_AS_HASH`.
The interface identifier is
`api_id = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_DEVBIND_LIMBS_V0_"`. This
gives domain separation from the standard byte-message interface. Credentials and proofs of the two interfaces do not verify against each other
(`test_profile_api_ids_do_not_mix`). Message types are fixed per index by the
profile, so a raw limb and a hashed attribute never share a position. Modular
BBS draft-03, which the report recommends, could not be retrieved
(SOURCES.lock). This interface is therefore local and is **not** claimed to be
Modular-BBS compatible.

**D-5 (engineering).** BBS core = editor's copy at the pinned fixture revision
(not the draft-10 text, which was unreachable). Gate: all 30 SHA-256 fixtures
pass (generators, P1 derivation, map-to-scalar, keygen, mocked RNG, 10
signature and 15 proof vectors including mocked-random proof generation).
Passing them validates only the byte-message core.

**D-6 (engineering + provisional).** Committed disclosure is Blind BBS
CoreProofGen/CoreProofVerify (editor's copy 56b032e) with
`commitment_indexes = (0,1,2,3)`, called directly as a core operation with our
`api_id` and the ordinary `create_generators(L+1, api_id)` generators. The
BlindSign / prover-blind machinery is not used because issuance is not blind.
Commitments: C_i = Y0·s_i + Y1·m_i with (Y0, Y1) =
create_generators(2, "COM_DIS_" || api_id).

**D-7 (engineering).** Prepare/finish split: `cd_prepare` performs
ProofInit (all random scalars, Abar, Bbar, D, T1, T2) and computes commitments and
their announcements C~_i. `cd_finish` only computes the challenge (hash) and
scalar responses. The published equations are unchanged. A test asserts that
`cd_finish` performs no group operations.

**D-8 (deviation from draft text).** The Blind-BBS `octets_to_proof`
pseudocode has inconsistent inclusive/exclusive index arithmetic. We implement
the evident layout: I2OSP(len,8) ‖ BBS proof ‖ I2OSP(N,8) ‖ N points ‖ N
scalars, with exact-length checks. Identity commitments and zero scalars are
rejected as in the draft.

## C. Cross-group transfer

**D-9 (provisional protocol, ported).** HPI `dleq_rok` with `bls_to_tom` parameters
b_x=128, b_c=112, b_f=8. Mask k ∈ [0, 2^248), z = k + c·m over the integers,
accept iff 2^240 ≤ z < 2^248. BLS key (Y1 message, Y0 blind) matches the BBS
commitments. One repetition per limb gives 2^-112 soundness per limb. Dock's
implementation asserts NUM_REPS·b_c ≥ 128, which would mean two repetitions.
We follow HPI and the report's 112-bit target and do **not** label the system 128-bit.
*Open:* decide whether to use two repetitions for a 128-bit target.

**D-10 (deviation from HPI).** The announcements (K1, K2) are transmitted
instead of the challenge, because the composed challenge digest hashes them.
The 112-bit challenge for limb j is the first 14 bytes of
SHA-256(Transcript(DST_TR; M, cp, j)) as a big-endian integer. This is not merlin and
is not byte-compatible with HPI.

**D-11 (provisional protocol, retry rule).** On any transfer abort, the whole
attempt is discarded without releasing anything. All **four** transfer
announcements are replaced with a fresh pre-computed spare set, and M, cp and
all challenges are recomputed. The device signature, BBS init and SM
announcements are reused because none of their responses were released.
Replacing only the aborted limb was rejected: re-using a non-aborted
announcement conditions its mask on an earlier acceptance event that depends on
the witness, which skews the final z distribution. Spare sets: 4 per slot.
Exhaustion burns the slot (probability ≈ (4·2^-8)^5 < 10^-9).

## D. Tom relation proof

**D-12 (provisional protocol).** Two profiles, never mixed. The profile id is in the statement,
in every challenge input, in the request, and checked on parse.
- `draft00-shared-bit`: PA challenge = SM bit; both PA branches precomputed
  offline; zero online curve operations.
- `separate-pa`: per-round PA challenge e_i ∈ Z_p = hash_to_field(DST_PA; M,
  cp, i), plus SM bits. Algebra as in the HPI reference, transcript ours.
  This is **not** the reference merlin transcript (the reference derives PA
  challenges sequentially per round). It is named `separate-pa`, not
  `reference-separate-pa`, to avoid implying interoperability.

**D-13 (engineering).** The honest prover samples ω ∉ {0, c, 2c}. A residual
exceptional addition (x(V) = x(Q)) makes `pa_prepare` raise, and ω is resampled
before anything is released. The verifier rejects α = 0 or α ≥ n and requires
U1 ≠ O (decode rejects identity at that position).
*Rust 0.3 after A3 (16 Oct 2026):* `sm::sm_prepare_rounds` computes V = U − Q and
calls `pa_prepare_with_slope`; the exclusions make every exceptional case
unreachable (U = O ⇔ ω = 0, V = O ⇔ ω = c, x(V) = x(Q) ⇔ ω ∈ {0, 2c}), so the
residual checks return an error instead of resampling.

**D-14 (finding F-1, see SOUNDNESS_ANALYSIS).** The SM/PA constraints with Opt 3
do not force the committed result onto the curve when U = −V (ω = c/2). A
prover that knows c can commit to an **off-curve** pair and pass every round
(`test_finding_F1_offcurve_result_accepted_by_standalone_sm`). In this
protocol, the committed coordinates are the issuer-signed limbs of a validated
on-curve key (D-1). With that, the PA constraints imply Q + V = U (SM-1).
In the composition, the transfer blocks the attack, conditional on the
composed knowledge soundness (C10/C11, open items O-K2, O-S3, G-1). An
end-to-end attempt is rejected at the transfer
(`test_offcurve_commitment_cannot_be_linked`). No code change was made. The
SM component must not be reused standalone for unvalidated result
commitments.

**D-15 (engineering).** The repetition count of 128 is fixed by the profile. The
parser rejects any other round count, so the proof cannot choose its own
security parameter.

## E. Signing, hashing and transcript

**D-16 (provisional protocol).** h = OS2IP(SHA-256(h_input)) mod n, where
h_input binds protocol id, profile, issuer pk, header, L, disclosed
(index, scalar) pairs, committed indexes, **Q′**, D_1..4 (BLS) and T_1..4 (Tom),
the verifier nonce nv, the request context ctx (audience, issuer pk, profile,
disclosed indexes) and a fresh 32-byte holder nonce nh. Rule for h = 0: the
holder resamples nh, and the verifier rejects h = 0.

**D-17 (provisional protocol).** The device raw-signs rep = I2OSP(c·h mod n, 32). The
device performs **no** hashing (ECDSA with e = OS2IP(rep), the Prehashed
interface). The holder publishes (r, s′) with s′ = a·s mod n, normalised to
low-s (s′ ≤ (n−1)/2). The verifier enforces 1 ≤ r < n and 1 ≤ s′ ≤ (n−1)/2 and runs
ordinary ECDSA verification under Q′ (OpenSSL) on representative h.

**D-18 (provisional protocol).** Composed challenge: M = SHA-256(Transcript(DST_M;
SHA-256(h_input), r, s′, transfer announcements, SM first messages)). The BBS
presentation header is ph = M, so the Blind-BBS challenge cp binds M plus all
BBS announcements and commitments. Transfer challenges and SM bits
(SHAKE-256(DST_SM; M, cp), first 128 bits, LSB-first per byte, as in the
reference) are derived from (M, cp). All first messages are fixed before any
challenge is derived (no per-round grinding). Proof responses and the final
proof bytes are never hashed (no circularity).

**D-19 (engineering).** Transcript encoding: length-prefixed labelled items
under a one-byte-length DST (`hashing.Transcript`), injective for a fixed
label schedule.

## F. State, device, verifier

**D-20 (engineering).** The software device runs in a separate process
(`multiprocessing` spawn). The private key is generated there and never sent.
The holder adapter exposes only `public_key()` and `sign_representative()`, and
`revoke()` models losing access. No real secure element was available
(PROGRESS.md). `VectorSigner` (in-process, deterministic) exists only for
reproducible test vectors and is labelled as such.

**D-21 (engineering).** Slot store: atomic rename reservation and
burn-on-reserve (the file is deleted before signing). Slots are keyed by
(profile, disclosure set), because a slot's BBS disclosure policy is fixed at
preparation. A request with a different policy needs another slot or a cold
preparation. State is unencrypted pickle (research only).

**D-22 (engineering).** Independent verifier =
`python -m devbind.verifier_cli` in a separate process, given only issuer
public parameters, the verifier's request and the presentation bytes.
`VerifierSession` adds single-use nonces (replay protection is verifier state).

**D-23 (engineering).** Randomness comes from `secrets` by default. A
deterministic SHAKE DRBG can be installed only by tests and vector generation
(`devbind.rng.deterministic`).

**D-24 (engineering).** Pure-Python backend only. No native backend was built,
so timings are reference-backend numbers and not deployment numbers.

## G. Open items carried into the analysis

- G-1: HT provenance. The source gives no generation procedure. x = 3, 4, 5
  and 7 are all on Tom-256, so "smallest x" is not the rule. Binding of Tom Pedersen commitments
  assumes log_GT(HT) is unknown.
- S-1: draft-10 text and Blind-BBS -03 text were not compared byte-for-byte
  with the editor's copies used.
- D-9 repetition count (112- vs 128-bit transfer target).
- Freshness reduction (SECURITY_ANALYSIS.md).

## H. Post-freeze changes (analysis feedback)

- A-1 holder credential validation; A-2 issuer n_attr bound; A-3 deferred SM
  point decoding in the verifier. Accept/reject outcome unchanged.
- Point additions are now counted in the online-ops instrumentation.
  Earlier counters covered only multiplications and MSMs.
- Review-driven tests: end-to-end F-1 composition attempt, parse-level range
  rejections, both-bit F-1 check.
