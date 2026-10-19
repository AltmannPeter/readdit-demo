# Design: BBS committed disclosures with proof plugins

Status: version 0.1 of this repository (October 2026). Research code, not production-ready.
Normative encodings and algorithms: `ENVELOPE.md` (framework), `plugins/ECDSA-POP.md`,
`plugins/DATE-RANGE.md` and `plugins/PSEUDONYM.md`.

## 1. Idea

An ETSI "BBS with Committed Disclosures" (CD) presentation can, instead of disclosing or
hiding an attribute m_j, **commit** to it. The commitment is a Pedersen commitment in
BLS12-381 G1:

  D_j = m_j·Y0 + s_j·Y1,

which the BBS proof binds to the credential. The holder knows the opening s_j.

A **plugin** proves a statement about the values behind some D_j and is bound to the same
presentation. Examples:

| Plugin | Statement about the committed values |
|---|---|
| `ecdsa-pop` (this release) | the committed P-256 key signed this request |
| `date-range` (this release) | the committed date (e.g. birth date) lies in a requested range: any age threshold or age range |
| `pseudonym` (this release) | nym = seed·H(configuration, relying party) for the committed seed |

The core does not know what a plugin proves. It knows only three things:
- which attributes a plugin needs committed;
- how to bind every plugin to one request;
- where each plugin's proof sits in the presentation.

## 2. Workspace

| Crate | Role | Depends on |
|---|---|---|
| `crates/bbs-cd` (lib `bbs_cd`) | ETSI CD v0.7 reference implementation (code, tests, fixtures), with two output-preserving performance changes (`crates/bbs-cd/README.md`) | — |
| `crates/bbs-cd-plugin` | schema, issuer, request, envelope, plugin traits, shared utilities (codec, transcript, parallelism, errors) | `bbs-cd` |
| `crates/cd-tom256` | toolkit for P-256 statements: Tom-256, BLS12-381 → Tom-256 transfer, scalar-multiplication (SM), point-addition (PA) and on-curve proofs, batching, fixed-base tables | `bbs-cd-plugin` |
| `crates/cd-ecdsa-pop` | the ECDSA proof-of-possession plugin: hashed mode (default) and raw mode | all of the above |
| `crates/cd-date-range` | the date-range plugin: `date-packed` attribute type and a bit-decomposition range proof in BLS12-381 | `bbs-cd-plugin` |
| `crates/cd-pseudonym` | the pseudonym plugin: `nym-seed.issuer-known` attribute type, pseudonym and Schnorr proof in BLS12-381 | `bbs-cd-plugin` |

A plugin that works natively in the BLS12-381 scalar field (date range, pseudonym) needs
only `bbs-cd-plugin`. `cd-tom256` is for statements in the P-256 fields.

## 3. Credential schema

The issuer fixes a **schema**: an ordered list of attributes. Each attribute occupies
consecutive BBS messages:

| Kind | Messages | Disclosable | Committable |
|---|---|---|---|
| `Octets` | 1 (OCTETS) | yes | no (v0.1) |
| `Scalars { type_id, count, bits }` | `count` (SCALAR, each < 2^bits) | no (v0.1) | yes |

- `type_id` names the attribute type, for example `p256-point-xy.ecdsa-sha256`. The plugin that owns
  the type provides an **attribute handler**, which the issuer uses to:
  - turn the input into scalars;
  - run the type's issuance checks (for the device-key types: device attestation
    including the key's permitted usage, a valid P-256 point, canonical limbs).
- The schema's canonical encoding goes into the BBS header, so the signature fixes the
  layout.
- **Reserved for later plugins:** `bits` up to 255 (a holder secret), and a `blind`
  flag for attributes the issuer signs without seeing them (blind issuance, needed for
  pseudonyms). v0.1 rejects `blind = true`.

The device-key types `p256-point-xy.ecdsa-sha256` (hashed mode only) and
`p256-point-xy.ecdsa-raw` (raw mode only) share the `p256-point-xy` layout: with limb
size b ∈ {64, 96, 128}, count = 2k, k = ⌈256/b⌉: x₀…x_{k−1}, y₀…y_{k−1}, little-endian.
This is the DEVBIND 0.3 layout. A type can also carry a policy, here the key's single
permitted signing mode, which the issuer checks and the signature then fixes.

## 4. Request

The verifier sends:

```
Request {
  audience, nonce (16..64 bytes),
  credentials: [ { issuer_pk, schema_digest, disclose: [attribute names] } ],   // 1..8
  plugins:     [ { plugin_id, credential, attribute, params } ],                // 0..16
}
```

- `params` are plugin-specific, for example the ECDSA mode, profile and transfer
  configuration. The plugin's verifier validates them.
- An attribute is **committed** iff some plugin references it.
- Every other attribute not in `disclose` is hidden.
- Two plugins may use the same attribute. Its D_j is then shared, and Pedersen binding
  makes the openings agree.

**Binding values:**
- ctx = Tr("…/request-context"; audience, every credential entry, every plugin entry,
  in order);
- ph = Tr("…/presentation-header"; nonce, ctx). It is the ETSI presentation header of
  every BBS proof in the presentation.

## 5. Statements and binding

For each credential i, after `PrecomputeCommitment`:

  cstmt_i = Tr("…/credential-statement"; issuer_pk, header, L, disclosed (index, scalar)*, committed indexes, D bytes)

  env = Tr("…/envelope-statement"; protocol id, ctx, cstmt_0, …, cstmt_n)

Each plugin receives `EnvContext { nonce, ctx, env, plugin_index }`, its request entry
and the committed inputs of its attribute. It must:

1. put its plugin id, `env`, its position `plugin_index`, its `params` and every value it
   reveals into the Fiat–Shamir transcript of its proof (domain-separated by its own
   tags);
2. bind the request nonce directly. ctx, and therefore env, does not contain it.

Because `env` contains every D_j and ctx, a plugin proof cannot be moved to another
presentation, another request, another position or another set of commitments. The
exact encodings and the full rule list are in `ENVELOPE.md` §5.

**Composition (informal).** If every plugin is knowledge-sound for its relation over the
D_j and zero-knowledge, and the rules above hold, then the presentation is sound and
zero-knowledge for the conjunction. The argument is the DEVBIND P2 composition argument,
applied once per plugin. The BBS-side open items stay in the core, once.

## 6. Presentation (envelope) encoding

```
"BCDP" 0x01
u8  n_credentials
    per credential: u16 n_disclosed, (u32-len value)*, u32-len BBS proof
u8  n_plugins                      (= request.plugins.len(), same order)
    per plugin: u8-len plugin_id, u32-len proof
```

- Every dimension is checked against the request and the schema.
- The verifier never takes a count from the presentation without comparing it.

## 7. Plugin interface

```rust
// bbs_cd_plugin::issuer
pub trait AttrHandler: Send + Sync {
    fn type_id(&self) -> &str;
    fn encode(&self, spec: &ScalarsSpec, input: &[u8]) -> Result<Vec<ScalarInput>>;
}

// bbs_cd_plugin::plugin
pub trait PluginVerifier: Send + Sync {
    fn plugin_id(&self) -> &[u8];
    fn check_request(&self, attr: &AttributeSpec, params: &[u8]) -> Result<()>;
    fn verify(&self, env: &EnvContext, view: &CommittedView, params: &[u8], proof: &[u8],
              rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>>;          // public output
}

pub trait PluginProver {
    fn plugin_id(&self) -> &[u8];
    fn prove(self: Box<Self>, env: &EnvContext, input: &CommittedInput, params: &[u8],
             rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>>;
}
```

| Type | Contents |
|---|---|
| `CommittedInput` | credential position, attribute spec; per message: index, scalar m_j, opening s_j, D_j |
| `CommittedView` | credential position, attribute spec; per message: index, D_j |

- The prover object holds the plugin's offline state (for example, prepared slots) and
  is consumed: single use. It may borrow (a device handle, a stats cell), so `present`
  takes `Box<dyn PluginProver + 'a>`.
- **Public output.** Pseudonyms and similar plugins return their public value through
  `verify`'s output; `Verified::outputs` lists them in request order.
- **Several credentials.** The envelope already allows them. A plugin that relates two
  credentials gets an extended view in a later version.
- **Template.** `crates/bbs-cd-plugin/tests/common/mod.rs` has a minimal plugin,
  `example-eq/0.1` (a Schnorr proof that a committed `uint` equals a public value), with
  its handler, prover and verifier. It is the starting point for a new plugin.

## 8. Holder flow

1. **Offline:**
   - `prepare_credential(cred, &[committed attribute names], rng)` runs
     `PrecomputeCommitment` (D_j, s_j), independent of any request, and returns a
     single-use `CredentialSlot`.
   - `slot.committed_input(cred, credential_position, attribute)` gives a plugin its
     `CommittedInput`. Plugins prepare their own state from it; for the raw ECDSA mode
     this includes the 128 SM rounds.
2. **Online:** `present(request, &[&cred], slots, provers, rng, stats)`:
   - validates the request against the credentials' issuers and each slot;
   - computes ctx, ph, cstmt and env (`holder_statements`, also usable on its own);
   - runs ETSI `ProofGen` per credential (independent of any device);
   - calls each plugin prover in request order;
   - encodes the envelope.

## 9. Verifier flow

`Verifier::new().register(Box::new(plugin_verifier))…`, then
`verify(issuers, request, presentation, rng, stats)`:

1. Validate the request against the issuers' parameters and the registered plugins
   (`check_request`).
2. Parse the envelope (`parse`).
3. For each credential: run `ProofVerify(ph, D)`.
4. Compute cstmt, env and each plugin's view (`verifier_statements`).
5. For each plugin: call `verify` with its view.
6. Return `Verified { disclosed, outputs }`.

`VerifierSession` keeps nonces single-use and expiring: `request(…)` issues and records
a request, `accept(nonce, presentation)` consumes the nonce, then verifies.

## 10. ECDSA plugin (`ecdsa-pop`)

The plugin specification is in `docs/plugins/ECDSA-POP.md`.

**Modes:**

| Mode | Status | Device call | What is proved | Assumption |
|---|---|---|---|---|
| `hashed` | default | standard ECDSA-P256-SHA256 on a message bound to the request | z·K = (h/r)·G + Q, with K revealed | ECDSA unforgeability; works with any secure element |
| `raw` | feature `raw-mode` | raw signature on c·h under the randomized key Q′ = a·Q | precomputable proof of Q′ = a·Q | KR-ECDSA; needs raw-digest signing, which Android KeyMint lists as deprecated |

A device key serves one mode only, fixed by its attribute type and attestation (review
finding H-2; `plugins/ECDSA-POP.md` §1). Profiles (`draft00-shared-bit`, `separate-pa`)
and the transfer configuration are verifier parameters, as in DEVBIND 0.3. **Wire format and protocol id are new;**
presentations aren't compatible with DEVBIND 0.3.1.

## 11. Date-range plugin (`date-range`)

The plugin specification is in `docs/plugins/DATE-RANGE.md`. The birth date is one
`date-packed` scalar, (Y − 1900)·372 + (M − 1)·31 + (D − 1), which compares like dates
without calendar arithmetic. The verifier sends `ge` and/or `le` as YYYYMMDD; the holder
proves lo ≤ m ≤ hi on the ETSI commitment D with one bit-decomposition range proof (the
Privacy Pass construction for an arbitrary limit), natively in BLS12-381. An 18+ check is
16 bits: 2,340 bytes. No per-threshold issuance or precomputation; there are no boolean
age attributes.

## 12. Pseudonym plugin (`pseudonym`)

The plugin specification is in `docs/plugins/PSEUDONYM.md`. A pseudonym is computed from
a seed, an optional prover input and a verifier input; the verifier names the
combination by a configuration identifier. Version 0.1 supports
`known-offender-matching-ssc`: the issuer-known seed (one `nym-seed.issuer-known`
scalar, issued like any attribute, so no blind issuance), no prover input, and the
relying party's identifier, which the wallet takes from the relying party's access
certificate and the prover enforces. nym = seed·OP with OP = hash_to_curve(configuration
‖ identifier); one Schnorr proof shows that the committed seed is behind both D and nym.
The proof is 148 bytes and takes about a millisecond on each side. The pseudonym is
unlinkable across relying parties for relying parties and outsiders, but not for the
issuer, by design.

## 13. Deployment requirements

The cryptography assumes the following of a deployment; none of it is enforced by the
library alone.

- **Shared issuer keys and schemas.** A request names the issuer key and the schema
  digest, and a presentation reveals both. An issuer that gave a holder its own key or
  schema could recognize that holder in every presentation, whatever the zero-knowledge
  properties of the proofs. Each issuer key and schema must be shared by a large
  population. Every issued attestation type must be registered in a public catalogue
  that fixes one schema and issuer key per anonymity set, and the wallet must refuse
  requests and credentials outside it. `cd-ecdsa-pop/tests/review_issuer_tag.rs` shows
  what happens without that rule: two credentials under one key but different schema
  ids are told apart by the schema digest.
- **Verifier randomness.** Batch verification in `ecdsa-pop` relies on unpredictable
  verifier randomness. Pass a cryptographic RNG or none (the default seeds ChaCha20 from
  the operating system).
- **Single-use nonces.** Use `VerifierSession` (or an equivalent store) so each nonce is
  accepted once. `accept` takes `&mut self`; a verifier serving requests concurrently
  must synchronize access to the session.
- **Relying-party identifier for pseudonyms.** Fix which access-certificate field, and
  which byte encoding of it, the wallet passes to `PseudonymProver::new`, and configure
  verifiers with the same value (`PseudonymVerifier::for_verifier`).
- **Test controls stay out.** Never build with `insecure-test-controls`, and never register
  a verifier from an `insecure_test_controls` module: the raw-mode `VariantVerifier` with
  the no-Q′ variant is deliberately unsound.
- **Raw mode is opt-in.** Verifiers accept `ecdsa-pop` raw mode only when built with the
  `raw-mode` feature (then `EcdsaPopVerifier::allow_raw` defaults to true and can be
  turned off). Deployments that don't need raw mode should build without it.

## 14. Future plugins: what they need from the core

| Plugin | Core support already there | Still needed |
|---|---|---|
| Pseudonym from a private seed, or with random prover input | the `pseudonym` plugin, configuration identifiers | private seed: blind issuance (`blind` flag, holder-side commitment at issuance, a signing entry point in the core); prover input: a configuration that allows it |
| Cross-credential equality | several credentials per envelope | a view spanning two credentials |
