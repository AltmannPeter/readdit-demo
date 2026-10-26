# Plan: demo profiles (rulebook versions, credentials, functions, flows)

Status: agreed plan, 2026-10-26. No code yet. Owner: Peter Altmann.

## Goal

Community must not be hardcoded to one rulebook version. Today v0.4 is spread over about 25
TypeScript files and the three Rust crates (doctype and schema ids, system ids, `zkp_req`, the
`fn_id`s, pseudonym configs, the registry, the statement derivation in `request.rs` and
`profile.rs`, the presentation codecs). v0.5 is expected within a month.

Decisions (Peter, 2026-10-26):

- A **demo profile** per version, selected by a switch in `/tech`; switching resets the demo.
- v0.4 stays runnable next to v0.5. Differences between versions are **modules**, not edits.
- Profiles are **JSON, checked against a JSON Schema** at start and on switch.
- Pseudonym configurations and every function request have their own definitions in the
  profile. A **request interpreter** derives what a request means from those definitions;
  the interpretation is not hardcoded.
- A **flow file** per profile describes the expected flow end to end, including the site side
  (accounts, gates, bans). It is for automatic checks and documentation only, not shown on the
  site.
- **ZKP for every doctype**: nym_auth, and in v0.5 PID and PhotoID, all through `zkp_req`.
- The version is shown in `/tech` and `/dev` only.
- Trust machinery (trust lists, issuer policy) stays as it is for now; the plan covers the ZKP parts.

## Expected v0.5 changes

- `birth_date` is replaced by `bdc`, a birth-date commitment: SHA-256(16-byte random salt ‖ the
  14-byte full-date as encoded in an mdoc MSO, i.e. CBOR tag 1004 + "YYYY-MM-DD"). The circuit
  checks the hash and uses the opened date only for predicates, as it uses `ssc`. Purpose:
  prevent accidental disclosure of the birth date.
- `psc` (private seed commitment) is added as an attribute; a pseudonym configuration over
  `psc` follows (c/france's "fully anonymous" setting will point to it).
- `age_check` asks for ages in years instead of `ge`/`le` dates. The circuit still checks dates;
  the applications translate years into date bounds (see "Functions").
- New credential types: PID and PhotoID, with circuits.
- nym-auth-circuits delivers the v0.5 Vega and Longfellow circuits (`bdc`, `psc`, age in years).
- BBS (`bbs_cd`): no format change yet; BBS already avoids accidental disclosure. The wallet
  must handle the new `age_check` request for BBS too, since the request is proof-system agnostic.
  Proposed: BBS presentations carry `proof_time` when the request asks for an age in years (it
  is already `? proof_time` in the CDDL; only its condition and the BBS registry entry change).
  The verifier derives the bounds from it, puts them in the BBS request it derives itself, and
  checks `proof_time` within the tolerance; the plugins do not change.

## 1. Profile files

```
profiles/
  schema/                       JSON Schemas for every file kind below
  nym-auth-v0.4/
    profile.json                id, label, rulebook version and date, protocol module, the parts below
    flow.json                   the expected flow (section 4)
    credentials/                nym_auth.mdoc.json, nym_auth.bbs.json
    functions/                  pseudonym.json, age_check.json
    pseudonym-configs/          known-offender-matching-ssc.json, …
    systems/                    vega.json, longfellow.json, bbs.json (today's registry entries + binding)
    phones.json, fixtures/      demo phones and their credentials
  nym-auth-v0.5/
    … the same, plus credentials/pid.json, photoid.json, the psc pseudonym config
```

- **Credential type.** Doctype or schema per encoding; each attribute with a role:
  `plain`; `secret-commitment` (`ssc`, `psc`: the wallet holds the seed); `value-commitment`
  (`bdc`: preimage layout, what the circuit may use once opened, never disclosable). Which
  functions it supports. Card label and colour. Trust anchors (unchanged mechanism).
- **Function.** `fn_id` and version, params JSON Schema per wire version, result type, attributes
  needed, and the four levels of section 3.
- **Pseudonym config.** Id, seed attribute (`ssc` or `psc`), PRFs per encoding, DST,
  `verifier_input` and `prover_input` derivations, and the properties now in
  `app/wallet/rulebook.ts` (distinct per verifier, issuer can link, …).
- **System.** Today's registry entry (`shared/registry/circuits.ts`): system id, proof system,
  addon, artifact hashes, library commits; plus a **binding**: which statement field feeds which
  public input or scheme parameter, through which operators.
- **Phones.** Which phone holds which credentials (today `PHONES` in `app/wallet/holder.ts`).

## 2. Request interpreter and statement

One module turns a request into its meaning, with no version knowledge of its own:

1. The protocol module of the profile's version reads the wire format (DCQL `zkp_req`).
2. The function definitions check each `_req` item against its params schema.
3. The steps listed in the function and pseudonym-config files produce a version-free
   **statement**, e.g.

   ```json
   { "credential": "nym_auth", "encoding": "mso_mdoc",
     "pseudonym": { "config": "known-offender-matching-ssc", "seed": "ssc", "prf": "sha-256", "verifier_input": "<32 bytes>" },
     "age": { "min_years": 13, "max_years": 17, "as_of": "proof_time" } }
   ```

The steps are named, versioned **operators** in code (e.g. `sha256(client_id)@1`,
`years_to_birthdate_bounds@1`, `cbor_full_date@1`, `bdc_open@1`); the data composes them. That is
the line between configuration and code: a new version can add operators, not change the
interpreter.

Users of the statement:

- **Site verifier:** what to expect and how to apply the results (the gates are already in years).
- **Wallet:** whether its credential can satisfy the request, and the consent screen.
- **Rust addons:** receive the statement (built by the server from its own session store, as
  now) and the system's binding; they keep only "statement → public inputs", the presentation
  encoding and the witness, and stop parsing requests.
- **Guide, `/tech`, `/dev`:** explanations from the same definitions.

The interpreter is TypeScript in `shared/`, so the server and the wallet in the browser run the
same code.

## 3. Function specifications (four levels)

| Level | Content |
| --- | --- |
| Request (wire) | params as sent, per version |
| Meaning | the predicate, independent of version |
| Translation | each step from meaning to what is proven, which actor runs it (verifier app, wallet, circuit) and from which input |
| Proof check | what the circuit or scheme actually proves |

Plus the result type and the edge rules (UTC dates, inclusive bounds, 29 February, clock source).

**age_check example.**

- Wire: v0.4 `{ ge, le }` dates; v0.5 ages in years.
- Meaning: the holder is between *a* and *b* years old on date *d*.
- Translation, v0.5: *d* is the date of `proof_time` (Peter, 2026-10-26). The wallet sets
  `proof_time`, computes the birth-date bounds from *a*, *b* and its date
  (`years_to_birthdate_bounds@1`), and proves with them. The verifier checks `proof_time`
  against its clock within the tolerance, as now, and recomputes the same bounds from it.
  v0.4: no translation; the bounds travel in the request.
- Proof check (both versions): the birth date (in v0.5 opened from `bdc`) lies in
  [lower, upper]. The circuit does not change for the age check.
- Time rules (Peter, 2026-10-26): `proof_time` is always UTC, `YYYY-MM-DDThh:mm:ssZ`, to the
  second, no offset (the code and the circuits already accept only this form; the rulebook's
  `tdate` should say so). The wallet sets it from its clock and decides whether it can meet an
  age request on the UTC date, always. The verifier checks it against its clock within the
  tolerance (300 s). Time-zone deviations are tolerated: a holder reaches an age at UTC midnight,
  not local midnight. Local-time handling is a later target, not v0.5.
- Edge case, accepted: within the tolerance of UTC midnight a wallet may choose a `proof_time` on
  either side of the date change, so a holder can gain at most one day at a birthday boundary.
- Possible later: round `proof_time` to the minute, against clock-skew fingerprinting.

## 4. Flow file

`flow.json` per profile: the contract the code, the tests and the docs follow.

- **Actors:** person, site page, site server (verifier), wallet, prover.
- **Steps** in order, each with an id (`request.fetch`, `request.verify-signature`,
  `system.select`, `consent`, `pin.unlock`, `device.sign`, `prove`, `response.encrypt`,
  `response.decrypt`, `verify`, `apply`, `account.create`, `gate.decide`, `ban.check`, …), the actor,
  the message, inputs and outputs, and the functions and protocol module it uses.
- **Failure branches** per step: condition, error or refusal code, next step.
- **Variants:** sign-up, log-in, age gate, community join, the `/dev` request, as sub-flows of
  one base flow.
- **Trace names:** the label each step writes to the session trace and the wallet trace.

A change to the flow (e.g. a PIN check before the presentation) is made in the flow file first.
The wallet's screen sequence and the server's checks follow it through a registry of step
implementations: an existing step needs only the flow file change; a new kind of step needs its
implementation.

**Checks.** The server and the wallet log step ids. After a flows-check run, a coverage check
fails the run when a step or failure branch in the flow file was never reached, or when a trace
holds an undeclared step or steps out of order. Everything in the flow is covered.

**Docs.** Generated per profile: a Mermaid sequence diagram and tables of steps and failures, as
Markdown in the repository. Not shown on the site.

## 5. Version modules

| Difference | Module |
| --- | --- |
| DCQL / `ZkpPresentation` wire format | `shared/protocol/zkp_req-0.4`, `-0.5` |
| New derivation steps (`bdc_open`, years to bounds) | operators, versioned by name |
| Circuit inputs and witness (`bdc` opening, `psc`) | Rust module per binding version, in the same addon |
| New circuits (v0.5 nym_auth, PID, PhotoID) | artifacts in the profile, pinned by hash |
| BBS | unchanged format; the wallet and verifier use the shared age translation |

The addons are built with every version's modules, so v0.4 stays runnable.

## 6. /tech and /dev

- `/tech`: "Demo profile" switch (`POST /api/tech/profile`). It checks that the loaded addons
  serve every system the profile names, loads that profile's circuits and keys if needed, and
  resets the demo (accounts, sessions, accepted proof systems, phones).
- `/tech`: the active profile's manifest: rulebook version and date, credential types and
  encodings, functions and versions, pseudonym configs, systems with library commits and artifact
  hashes, the build commit.
- `/dev`: the profile and rulebook version.
- Measurements, profiles and trusted issuers carry the profile id; the Benchmark filters by it.

## 7. Phases

1. Schemas and the v0.4 profile: data, function specs, flow file, interpreter, statement.
   Acceptance: today's Request Objects and presentations come out byte-identical (saved copies),
   and the full suite passes.
2. Step registry, step ids in the traces, flow coverage check in flows-check, generated docs.
3. `/tech` switch with reset, manifest, version in `/dev`, profile id on records; flows-check
   per profile.
4. Rust addons work from the statement and the binding.
5. v0.5 profile: age in years (translation in the apps, BBS included), `bdc`, `psc`, the psc
   pseudonym config, PID and PhotoID, with the v0.5 circuits.

Phases 1 to 4 do not depend on v0.5 and can start now.

## Open

- BBS and age in years: confirm the proposal above (`proof_time` in BBS presentations when an
  age in years is asked). Alternatives: the verifier's date in the request, or the verifier
  accepting bounds for its date and the day before.
- PID and PhotoID: which functions over each (age, pseudonym, other predicates), and their
  doctypes and circuits from the v0.5 delivery.
