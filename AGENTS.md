# Agent guide: Readdit pseudonym and age demo

Read this before changing anything. It records the decisions so far, the current state, and what
is left. The owner is Peter Altmann (SIROS Foundation). He knows the cryptography in depth and will
check protocol claims, so cite the rulebook section when you rely on it.

## 1. What this is

A Reddit-style demo site, **Readdit**, for a 15-minute talk to a non-technical audience. The talk
has to show two things:

- Pseudonymous presentations from the EU Digital Identity Wallet are a workable alternative to
  presenting identity data.
- A production-ready zero-knowledge implementation (Longfellow) runs behind the demo.

The person uses Readdit on a computer and an identity wallet on their phone for every identity step,
over cross-device OpenID4VP (QR code).

- **Sign up and log in** with a pseudonym derived from the `eu.europa.ec.eudi.nym_auth.1`
  attestation. The pseudonym is the account identifier. There is no email, password or name.
- **Age-gated communities.** `c/teenspace` requires 13–17 and `c/afterdark` requires 18+.
- **Ban.** A moderator bans the account. The same wallet always yields the same pseudonym for
  Readdit, so signing up again lands on the banned account (known-offender matching within one site).
- **Interfaces are mocked, transactions are real.** The site and phone UIs are mocked. The OpenID4VP
  request and response, proof generation and proof verification are real, and the last two run as
  **local containerized services**.

The phone on screen is part of the website UI. It plays the person's wallet. In the real world the
wallet would build the proof on the phone. Here the prover service builds it, and it holds the
holder's credential, device key and seed in place of the phone's secure hardware.

### Source documents

- `nym_auth_rulebook.md` – Nym-authentication Attestation Specification and Rulebook v0.2. This is
  normative for the attestation, the `circuit_zk` DCQL profile, capability negotiation,
  `pseudonym-v1-sha256`, `age_check`, presentation encoding, verification and binding. In the shared
  package it is `docs/nym_auth_rulebook.md`. In Peter's workspace it is in the parent folder
  (`pseudonym_demo/`).
- `NYM-AUTH.md` (Peter's workspace only) – benchmarks for the full nym_auth statement. On mdoc,
  Longfellow (Google Rust, 1 thread) takes about 0.9 s end to end and produces a proof of about
  345 KB. Peter shows these on a slide; the site does not need to reproduce them.

## 2. Decisions (do not change without asking Peter)

| Topic | Decision |
| --- | --- |
| Stack | Nuxt 4, TypeScript, Tailwind v4, Nitro server routes. Node `^22.22.3` or `>=24.15`. |
| Backend | Prover and verifier run as local containers (`docker-compose.yml`). The contract is in `docs/backend-api.md`. The demo uses Longfellow. |
| Proof system | Longfellow for the demo. The full `circuit_zk` DCQL extension is implemented, including capability negotiation. The registry also lists Vega so negotiation can be shown. |
| Brand | Site name "Readdit", lowercase wordmark "readdit", original logo. Communities are prefixed `c/`. Do not use Reddit's logo, mascot or `r/`. |
| Wallet look | Generic phone with no brand marks. App name "EUDI Wallet App", grey-blue palette (`--color-w-*`), no logo. |
| Audience | The main Readdit window is consumer UI only. Technical detail lives only in separate windows: `/tech`, `/mod`, and the credential window `/wallet/credential`. |
| Copy | Tight and plain. It must not sound like marketing or AI-written text. |
| Flow | Nothing is scripted. Each community has a gate `{ minAge?, maxAge? }` and the site reacts to any click order. |
| Credential | One `nym_auth` attestation covers both pseudonym and age. |
| Pseudonym config | `known-offender-matching-ssc` with `verifier_id_type: x509_san_dns`. `client_id = x509_san_dns:<siteHost>` is also the `verifier_id`. |
| Age binding | Every age request also asks for the pseudonym in the same `req`. The site accepts the age result only if the pseudonym equals the logged-in account's pseudonym. |
| 2FA | Every proof needs the device key and the wallet PIN (6 digits, default `123456`, `DEMO_PIN` on the prover). A wrong PIN is rejected by the prover service. |
| Unsatisfiable age | The wallet shows "Requirement not met" and sends `access_denied` with no description. The site cannot tell this apart from the user cancelling. |
| Errors independent of holder data | Unsupported request or no common circuit → the wallet sends `invalid_request` (rulebook allows `invalid_request` here). |
| Gate logic | The site stores the intersection of proven birth-date intervals and decides per gate: `allow`, `deny` (no overlap, so it refuses without asking the wallet), or `ask` (`shared/utils/age.ts`). |
| Ban | A ban is keyed by pseudonym. It ends the login, hides the account's comments, and blocks sign-up and age checks. |
| Offline backup | A built-in simulation of both services (`server/utils/offline-backend.ts`) for when containers or the network fail. Switch in `/mod` or start with `NUXT_BACKEND_MODE=offline`. It checks the PIN and the age predicate, derives the real pseudonym, sends a random proof of Longfellow's size, waits as long as the benchmark model says, and labels every metric simulated. No external requests at runtime. |
| Estimates | `/tech` shows per-step estimates from `shared/benchmarks.ts`. Desktop figures are measurements on Apple M5 and AMD Ryzen 9 (`NYM-AUTH.md`, `vega-caching-analysis.md`). Phone = desktop × 1–5, not measured; only phone-side steps are scaled. |

### Presentation order (not hardcoded)

1. Log in / sign up with QR, scan, consent and PIN. Optionally open the credential window from the
   phone's "Age and pseudonym" card.
2. Browse the open communities.
3. Open `c/afterdark` (18+). The wallet says "Requirement not met" and the site shows "Not completed".
4. Open `c/teenspace` (13–17). Access is granted. `c/afterdark` is now refused by the site itself.
5. Comment in `c/teenspace`. In the `/mod` window, ban the user. The user window shows the ban.
6. Sign up again with the same wallet. The site shows "Account banned".

`/tech` shows each step live: the request, the negotiation, the circuit, sizes and times.

## 3. Current state

```
app/
  components/WalletModal.vue     site dialog: QR, polls the server session, completes it for this browser
  components/wallet/App.vue      EUDI Wallet App: scan → POST request_uri (wallet_metadata) → verify JWS →
                                 check request + select circuit → consent → PIN → prove → POST response_uri
  components/wallet/*.vue        wallet screens
  wallet/engine.ts               wallet-side rulebook checks, circuit selection, age display
  wallet/transport.ts            HTTP transport; verifies the signed Request Object (ES256, x5c, SAN = host)
  wallet/prover.ts               calls /api/wallet/prove
  wallet/holder.ts               credential view types (data comes from the prover service)
  composables/useAccount.ts      account from /api/me
  pages/tech.vue                 technical view (separate window)
  pages/mod.vue                  moderation: comments, accounts, ban/unban, reset demo (separate window)
  pages/wallet/credential.vue    nym_auth details in human-readable form (popup from the phone)
server/
  utils/services.ts              THE ONLY CODE THAT CALLS THE BACKEND SERVICES (or the offline simulation)
  utils/offline-backend.ts       built-in offline simulation of prover and verifier
  utils/backend-mode.ts          services | offline, phone factor (runtime switch, /api/demo/backend)
  utils/request-signer.ts        signs Request Objects (ES256, x5c); self-signed cert unless PEMs configured
  utils/store.ts                 in-memory sessions, accounts, comments (reset with /api/demo/reset)
  utils/vp.ts                    verifier offer (config ∩ registry ∩ verifier /info), session helpers
  api/vp/session.post.ts         create session → { id, authorizationUrl }
  api/vp/request/[id].ts         request_uri, GET or POST (wallet_metadata, wallet_nonce), returns signed JWT
  api/vp/response/[id].post.ts   response_uri (direct_post), calls the verifier service
  api/vp/session/[id]*.ts        status polling and completion (login / age proof / ban / mismatch)
  api/wallet/*.ts                mocked phone → prover service (credential, capabilities, prove)
  api/me, logout, notice, comments, mod/*, demo/reset, tech/overview
shared/
  benchmarks.ts                  timing/size model for /tech estimates and the offline simulation
  registry/circuits.ts           approved circuit registry: Longfellow and Vega nym_auth entries, public inputs
  utils/negotiation.ts           tailorFormats (verifier side), selectCircuit (wallet side)
  utils/dcql.ts                  credential query, Request Object, authorization URL (request_uri_method=post)
  utils/pseudonym.ts             pseudonym-v1-sha256, all four configs
  types/oid4vp.ts                protocol types
backend-stubs/prover, verifier   stub services implementing docs/backend-api.md (no ZK proof)
docker-compose.yml               stub services on :8081/:8082; profile `full` adds the site on :3000
docker-compose.longfellow.yml    override: Longfellow images instead of the stubs
Dockerfile                       the site's container image
scripts/demo-flow.mjs            headless run of the presentation order with screenshots
```

What is real: the OpenID4VP request/response flow, signed Request Objects, capability negotiation,
DCQL `circuit_zk` checks on both sides, the CBOR presentation encoding, the pseudonym derivation,
the PIN check, accounts, bans and gate logic. What is stub: proof generation and proof verification
(the stubs say so in `/info`, and `/tech` shows a STUB badge).

## 4. What needs to be done

1. **Replace the stub containers with the Longfellow prover and verifier.** Implement
   `docs/backend-api.md`. Report real metrics (`load_ms`, `witness_ms`, `prove_ms`, `verify_ms`,
   `proof_bytes`, `peak_memory_mb`) because `/tech` shows them. The prover must sign
   `DeviceAuthentication` over `SessionTranscript = [null, null, OpenID4VPHandover]`, with
   `OpenID4VPHandover = ["OpenID4VPHandover", SHA-256(CBOR([client_id, nonce, jwk_thumbprint, response_uri]))]`
   (OpenID4VP 1.0 Appendix B.2.6; check this against the spec text).
2. **Confirm the registry values** in `shared/registry/circuits.ts` with Peter: circuit ids, proof
   system ids, and the public-input order. They must match what the services load.
3. **Issue a real demo `nym_auth` mdoc** (demo IACA and Document Signer, `birth_date` 2011-03-14,
   `ssc = SHA-256(secret_seed)`) for the prover. Give the verifier the trust anchor.
4. **Optional: a configured request-signing certificate** (`NUXT_REQUEST_SIGNING_KEY` and
   `NUXT_REQUEST_SIGNING_CERT`). The leaf needs dNSName SAN = `siteHost`. The mocked wallet does not
   check the trust chain.
5. **Projector check.** The dialog is about 690 px tall. Test at the venue resolution.

## 5. Rules for changing the code

- Keep the UI and copy as they are unless asked. They have been reviewed.
- Only `server/utils/services.ts` knows the service URLs. Keep it that way.
- The site must take `request` and `handover` from its own session store when verifying, never
  from the wallet's response.
- Do not add protocol details to the main Readdit window.
- Do not hardcode the demo order or the persona's age in site logic.
- Shared logic goes in `shared/`, imported as `#shared/...`.
- `@peculiar/x509` needs `reflect-metadata` loaded first. Import both dynamically, as
  `request-signer.ts` and `wallet/transport.ts` do; static imports get reordered or tree-shaken.

## 6. Running and testing

See `GETTING-STARTED.md` for starting the demo and using the three views. Short version:

```sh
npm install
npm run stubs                 # or: docker compose up -d --build   (stub services)
npm run dev                   # http://localhost:3000
# everything in containers: docker compose --profile full up -d --build
# Longfellow images: add -f docker-compose.longfellow.yml (LONGFELLOW_PROVER_IMAGE, LONGFELLOW_VERIFIER_IMAGE)
# separate windows: /tech  /mod ; the phone's credential card opens /wallet/credential
```

`scripts/demo-flow.mjs` runs the presentation order headlessly, including the wrong PIN, the ban and
the second sign-up, and saves screenshots. It needs Playwright:
`npm i -D playwright && npx playwright install chromium`, then `node scripts/demo-flow.mjs http://localhost:3000`.
Run it and `npx nuxi typecheck` after every change.
