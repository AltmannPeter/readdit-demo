# `BBS-CD-PLUGINS/0.1`: envelope specification

Normative description of the framework in `crates/bbs-cd-plugin`: encodings, binding
values, the presentation format, and the holder and verifier algorithms. `DESIGN.md`
explains the reasoning; plugin specifications live in `docs/plugins/`.

Status: research specification, version 0.1. There are no test vectors yet. Where this
text and the code disagree, the code is what was tested; please report the difference.

## 1. Notation

- `‖` is concatenation. `u8`, `u16`, `u32` are unsigned big-endian integers of 1, 2, 4
  bytes.
- `var8(x)`, `var16(x)`, `var32(x)` are `u8`/`u16`/`u32` length ‖ x.
- **ETSI** means *BBS with Committed Disclosures*, draft v0.7, as implemented in
  `crates/bbs-cd`, with ciphersuite BLS12-381-SHA-256 (`api_id` from that suite). The
  draft text is not redistributed here.
- A **scalar** is a 32-byte big-endian integer < r (the BLS12-381 group order).
- A **G1 point** is 48 bytes, compressed (ETSI `point_to_octets_E1`).
- **Transcript.** `Tr(dst; l₁ = v₁, …, lₙ = vₙ)` is the byte string

  ```
  u8 len(dst) ‖ dst ‖ ( u8 len(lᵢ) ‖ lᵢ ‖ u32 len(vᵢ) ‖ vᵢ )*
  ```

  with 1 ≤ len(dst) ≤ 255, len(lᵢ) ≤ 255 and len(vᵢ) < 2³². Labels are ASCII. `H(Tr(…))`
  is SHA-256 of that string. Fields are listed in the order they are written.

**Framework identifiers** (`params.rs`):

| Name | Value |
|---|---|
| FRAMEWORK_ID | `BBS-CD-PLUGINS/0.1` |
| DST_SCHEMA | `BBS-CD-PLUGINS/0.1/schema` |
| DST_HDR | `BBS-CD-PLUGINS/0.1/credential-header` |
| DST_CTX | `BBS-CD-PLUGINS/0.1/request-context` |
| DST_PH | `BBS-CD-PLUGINS/0.1/presentation-header` |
| DST_CSTMT | `BBS-CD-PLUGINS/0.1/credential-statement` |
| DST_ENV | `BBS-CD-PLUGINS/0.1/envelope-statement` |
| MAGIC | `BCDP` 0x01 |

A plugin uses its own DSTs. They must not start with `BBS-CD-PLUGINS/`.

## 2. Schema

A schema is an id and an ordered list of 1..64 attributes. Names (schema id, attribute
names, type ids) are 1..64 bytes of `[a-z0-9._-]`. Attribute names are unique.

| Kind | Code | Messages | Fields |
|---|---|---|---|
| `Octets` | 0 | 1 OCTETS message, ≤ 4096 bytes | — |
| `Scalars` | 1 | `count` SCALAR messages, each < 2^`bits` | `type_id`, `count` ∈ [1, 128], `bits` ∈ [1, 255], `blind` |

- `blind` is reserved for blind issuance and must be 0 in version 0.1.
- The attributes occupy consecutive message indexes in schema order. The total L is at
  most 128.

**Encoding:**

```
schema    = var8(id) ‖ u8 n ‖ attribute*n
attribute = var8(name) ‖ 0x00                                                   (Octets)
          | var8(name) ‖ 0x01 ‖ var8(type_id) ‖ u16 count ‖ u16 bits ‖ u8 blind  (Scalars)
```

A decoder re-encodes and rejects anything that is not byte-identical (canonical form).

**Digest:** `schema_digest = H(Tr(DST_SCHEMA; "schema" = schema))`.

## 3. Issuer parameters and credentials

- `IssuerParams = var8(pk) ‖ var16(schema)`, where pk is the 96-byte ETSI public key.
- **Header** (the ETSI `header` of every signature and proof):

  ```
  header = Tr(DST_HDR; "protocol" = FRAMEWORK_ID, "api_id" = api_id,
                       "L" = u16 L, "schema" = schema)
  ```

  The signature therefore fixes the framework, the suite and the full layout.
- **Issuance.** Message j of an `Octets` attribute is the value; the messages of a
  `Scalars` attribute are produced by the **attribute handler** registered for its
  `type_id`. The handler validates the issuance input and returns exactly `count`
  scalars, each < 2^`bits`. The issuer refuses if no handler is registered for a type
  in the schema. Signing is ETSI `Sign(sk, pk, header, messages, types)`.
- **Holder check.** A credential is accepted if the layout matches the schema (every
  OCTETS ≤ 4096 bytes; every scalar < 2^`bits`) and ETSI `Verify` passes.

## 4. Request, ctx and ph

```
Request {
  audience     (≤ 1024 bytes)
  nonce        (16..64 bytes, fresh per request)
  credentials  1..8 × { issuer_pk, schema_digest, disclose: [Octets attribute names] }
  plugins      0..16 × { plugin_id (1..64 bytes), credential (u8), attribute, params (≤ 1024 bytes) }
}
```

**Encoding:**

```
body    = u8 n_c ‖ ( var8(issuer_pk) ‖ schema_digest (32) ‖ u8 n_d ‖ var8(name)*n_d )*n_c
          ‖ u8 n_p ‖ ( var8(plugin_id) ‖ u8 credential ‖ var8(attribute) ‖ var16(params) )*n_p
request = var16(audience) ‖ var8(nonce) ‖ body
```

**Validity** (`Request::validate`, given one IssuerParams per requested credential):
- every length and count is within the limits above;
- each credential's `issuer_pk` and `schema_digest` equal its issuer's;
- `disclose` names `Octets` attributes, strictly in schema order (so no duplicates);
- each plugin's `credential` is in range and its `attribute` is a `Scalars` attribute;
- no two plugin entries have the same (plugin_id, credential, attribute).

The verifier also requires every `plugin_id` to be registered and runs that plugin's
`check_request(attribute spec, params)`.

**Disclosure states.** For credential i, an attribute is:
- **committed** if some plugin entry names (i, attribute); all its messages get ETSI
  state COMMIT;
- **disclosed** if it is in `disclose`; its message gets DISCLOSE;
- **hidden** otherwise; HIDE.

Two plugins may name the same attribute; they then share its D_j.

**Binding values:**

```
ctx = Tr(DST_CTX; "protocol" = FRAMEWORK_ID, "audience" = audience, "body" = body)
ph  = Tr(DST_PH;  "nv" = nonce, "ctx" = ctx)
```

ph is the ETSI presentation header of every BBS proof in the presentation.

## 5. Statements

For credential i, let
- `c_idx` be its committed message indexes and `d_idx` its disclosed ones, ascending;
- `D_j` (j ∈ c_idx) be its commitments, as 48-byte G1 points in index order;
- `m̂_j` (j ∈ d_idx) be the ETSI message scalars of the disclosed values
  (`messages_to_scalars` with the suite's `api_id`).

```
cstmt_i = Tr(DST_CSTMT; "issuer_pk" = pk_i, "header" = header_i, "L" = u16 L_i,
             "disclosed" = ( u16 j ‖ m̂_j )* over d_idx,
             "committed" = ( u16 j )*       over c_idx,
             "D"         = D_j*             over c_idx)

env = Tr(DST_ENV; "protocol" = FRAMEWORK_ID, "ctx" = ctx, "n_credentials" = u8 n,
         "credential" = cstmt_0, …, "credential" = cstmt_{n−1})
```

The holder computes env from its own D_j before any proof; the verifier recomputes it
from the D_j inside the BBS proofs. Both get the same bytes for an honest presentation.

**What a plugin receives** for plugin entry p (0-based position in `Request::plugins`):

| Value | Holder | Verifier |
|---|---|---|
| `EnvContext` | nonce, ctx, env, plugin_index = p | same |
| attribute | the `AttributeSpec` | same |
| params | the request's bytes | same |
| committed messages, in index order | index j, m_j, opening s_j, D_j (`CommittedInput`) | index j, D_j (`CommittedView`) |
| randomness | prover RNG | verifier RNG (for example, batch weights) |

**Binding rules** (every plugin must follow them):
1. Its Fiat–Shamir transcript contains, under the plugin's own DSTs: its `plugin_id`,
   env (or H(env)), `plugin_index`, `params` and every value the proof reveals. (The
   attribute name is already fixed by env and `plugin_index`; `ecdsa-pop` includes it
   anyway.)
2. It binds the nonce directly. env contains ctx, but ctx does not contain the nonce, so
   the nonce must go into the transcript or into a value signed for the request.
3. Its proof is a deterministic function of what is listed above, its own randomness and
   its own secrets. It reads no other part of the presentation.
4. Its verifier parses strictly: every length comes from the attribute spec and params,
   trailing bytes are rejected, every scalar and point is canonical.
5. Its public output (possibly empty) is a function of the proof and its inputs, and is
   bound by rule 1.

Because env contains ctx and every credential's header, disclosed scalars, committed
indexes and D_j, a plugin proof cannot be moved to another request, another position,
another credential or another set of commitments.

## 6. Presentation encoding

```
presentation = MAGIC
             ‖ u8 n_c ‖ ( u16 n_d ‖ var32(disclosed value)*n_d ‖ var32(BBS proof) )*n_c
             ‖ u8 n_p ‖ ( var8(plugin_id) ‖ var32(plugin proof) )*n_p
```

- Credentials and plugins appear in request order.
- Disclosed values are the raw OCTETS, in `disclose` order.
- The BBS proof is the ETSI proof encoding; it carries the commitments D_j.

**Limits:** presentation ≤ 4 MiB; BBS proof ≤ 16 KiB; plugin proof ≤ 1 MiB; disclosed
value ≤ 4096 bytes.

## 7. Holder

**Offline**, per credential (`prepare_credential`): run ETSI
`PrecomputeCommitment(messages of the committed attributes, their indexes, types)`,
giving D_j and openings s_j. The result is single use and independent of any request.
Plugins prepare their own state from the committed inputs (`CredentialSlot::committed_input`).

**Online** (`present`):
1. Validate the request against the credentials' issuers. Check that each slot commits
   exactly `c_idx` and that the provers match the plugin entries in order.
2. Compute ctx, env (§5) and ph (§4).
3. Per credential: ETSI `ProofGen(pk, signature, header, ph, messages, types, states,
   precomputed openings s_j)`. If ProofGen reports the negligible zero-response case,
   retry with fresh masks and the same openings (at most 4 attempts). Check that the
   proof's commitments equal the precomputed D_j.
4. Per plugin entry p: call the prover with `EnvContext{nonce, ctx, env, p}`, its
   committed input and params.
5. Encode (§6).

The BBS proofs do not depend on any plugin, and the plugins see only env, so steps 3 and
4 are independent of each other.

## 8. Verifier

`Verifier::verify(issuers, request, presentation)`; `issuers` follows `request.credentials`.

1. **Request.** Validate it (§4), check every plugin is registered, and run each plugin's
   `check_request`.
2. **Parse.** Strictly (§6): the magic; n_c and n_p equal to the request; each n_d equal
   to |d_idx|; each BBS proof decodes and has exactly |c_idx| commitments; each
   plugin_id equal to the request's; no trailing bytes.
3. **BBS.** Per credential: ETSI `ProofVerify(pk, proof, header, ph, disclosed, D, types,
   states)`.
4. **Statements.** Recompute cstmt_i and env from the parsed D_j and disclosed values.
5. **Plugins.** Per entry p: build the view (indexes and D_j of its attribute) and call
   the plugin's `verify` with `EnvContext{nonce, ctx, env, p}`. Any error rejects.
6. **Result.** The disclosed (name, value) pairs per credential and each plugin's
   output.

`verify` is stateless. Replay protection is verifier state: `VerifierSession` issues
requests with fresh nonces, accepts at most one presentation per nonce and expires
unanswered requests (default 300 s, at most 10,000 outstanding).

## 9. Registered identifiers

| Kind | Identifier | Specification |
|---|---|---|
| plugin | `ecdsa-pop/0.1` | `docs/plugins/ECDSA-POP.md` |
| attribute types | `p256-point-xy.ecdsa-sha256`, `p256-point-xy.ecdsa-raw` | `docs/plugins/ECDSA-POP.md` §1 |
| plugin | `date-range/0.1` | `docs/plugins/DATE-RANGE.md` |
| attribute type | `date-packed` | `docs/plugins/DATE-RANGE.md` §1 |
| plugin | `pseudonym/0.1`, configuration `known-offender-matching-ssc` | `docs/plugins/PSEUDONYM.md` |
| attribute type | `nym-seed.issuer-known` | `docs/plugins/PSEUDONYM.md` §1 |
| plugin (test only) | `example-eq/0.1`, type `uint` | `crates/bbs-cd-plugin/tests/common/mod.rs` |

A new plugin picks a versioned `plugin_id`, its attribute types, its own DST prefix and
a proof magic, and documents its encoding and binding in `docs/plugins/`.
