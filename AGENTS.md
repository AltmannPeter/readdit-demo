# Agent guide: Readdit pseudonym and age demo

Read this before changing anything. It records the decisions so far, the current state, and what
is left. The owner is Peter Altmann (SIROS Foundation). He knows the cryptography in depth and will
check protocol claims, so cite the rulebook section when you rely on it.

## 1. What this is

A Reddit-style demo site, **Readdit**, for a 15-minute talk to a non-technical audience. The talk
has to show two things:

- Pseudonymous presentations from the EU Digital Identity Wallet are a workable alternative to
  presenting identity data.
- A real zero-knowledge implementation runs behind the demo: Vega (Microsoft vega-prover) with the
  nym_auth circuits of the nym-auth-circuits archive. (Longfellow until 2026-10-13; see section 2.)

The person uses Readdit on a computer and an identity wallet on their phone for every identity step,
over cross-device OpenID4VP (QR code).

- **Sign up and log in** with a pseudonym derived from the `eu.europa.ec.eudi.nym_auth.1`
  attestation. The pseudonym is the account identifier. There is no email, password or name.
- **Age-gated communities.** `c/teenspace` requires 13–17 and `c/afterdark` requires 18+.
- **Ban.** A moderator bans the account. The same wallet always yields the same pseudonym for
  Readdit, so signing up again lands on the banned account (known-offender matching within one site).
- **Interfaces are mocked, transactions are real.** The site and phone UIs are mocked. The OpenID4VP
  request and response, proof generation and proof verification are real. The last two run in the
  site's server, in a Rust Node addon (`native/vega`).

The phone on screen is part of the website UI. It plays the person's wallet, the SIROS ID wallet.
In the real world the wallet would build the proof on the phone. Here the Vega prover in the site's
server builds it. There is no true holder binding: the mocked wallet carries the credential, the
device key and the seed outright (`app/wallet/demo-wallet.json`) and sends what each native step
needs; the prover keeps none of it.

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

On 2026-10-13, at Frédéric's request, Vega and the SIROS ID wallet look replaced the earlier
decisions on the backend, the proof system and the wallet look (Longfellow in local containers, and
a generic unbranded "EUDI Wallet App"). Later the same day, also at his request, the wallet's
screens took the SIROS ID wallet's own layout and strings, and a guide panel beside the site took
over the technical commentary (rows Consent, Audience, Copy and Guide). The rows below are the
current decisions; the replaced ones are quoted in them.

| Topic | Decision |
| --- | --- |
| Stack | Nuxt 4, TypeScript, Tailwind v4, Nitro server routes. Node `^22.22.3` or `>=24.15`. Rust (stable) for the proof addon. |
| Backend | **Replaced 2026-10-13 (Frédéric):** the prover and verifier are a Rust Node addon (napi-rs, `native/vega`) that the site's server loads; `server/utils/services.ts` is the only caller. Two separate objects, each building its keys once at start. The contract is in `docs/backend-api.md`. Was: "Prover and verifier run as local containers. The demo uses Longfellow." |
| Proof system | **Replaced 2026-10-13 (Frédéric):** Vega (`vega-v1`, microsoft/vega-prover `c0ee259`) with the nym-auth-circuits `vega-age` circuits, vendored unchanged, circuit `urn:circuits:vega:nym_auth:v1`. The full `circuit_zk` DCQL extension is implemented, including capability negotiation; the registry still lists Longfellow so negotiation can be shown. Was: "Longfellow for the demo." |
| Brand | Site name "Readdit", lowercase wordmark "readdit", original logo. Communities are prefixed `c/`. Do not use Reddit's logo, mascot or `r/`. |
| Wallet look | **Replaced 2026-10-13 (Frédéric):** the SIROS ID wallet (sirosfoundation/wallet-frontend, BSD-2-Clause): its screens, colours (`--color-sid-*`), Inter, lucide icons and logo, attributed in `app/components/wallet/THIRD-PARTY-NOTICES.txt`. The phone frame stays generic. Was: "Generic phone with no brand marks. App name 'EUDI Wallet App', grey-blue palette, no logo." |
| Consent | **Replaced 2026-10-13 (Frédéric):** the wallet's request screen is the SIROS ID one: the requester (name and domain) and the requested information in product wording, derived from the request: a pseudonym specific to the site and, only when asked, the age range computed from the request's bounds. The technical account of the same request (the pseudonym and the rulebook's properties of its configuration, what is not shared, the other values the verifier receives, `client_id` and the signing certificate) is in the guide panel's Details. All of it comes from `consentFor` (`app/wallet/engine.ts`). Was: "The wallet's request screen shows what the request actually discloses: the verifier (name, host, `client_id`, signing certificate), the pseudonym the wallet computes for this site with the rulebook's properties, the age range if asked, the other public inputs, and what is not shared." |
| Audience | **Replaced 2026-10-13 (Frédéric):** the main window shows the product (Readdit and the SIROS ID wallet) with product copy only, and the guide panel beside it. Technical detail lives in the guide's Details and in the operator pages `/tech` and `/mod`. The credential window `/wallet/credential` is gone. Was: "Technical detail lives only in separate windows: `/tech`, `/mod`, and the credential window `/wallet/credential`." |
| Copy | Tight and plain. It must not sound like marketing or AI-written text. The wallet uses the SIROS ID wallet's English strings (`src/locales/en.json`) wherever one exists; screens the real wallet lacks ("Requirement Not Met") are written in the same style. |
| Guide | **Added 2026-10-13 (Frédéric):** a guide panel docked at the right edge, styled apart from the product, collapsible. It follows the flow state by itself (`app/guide/steps.ts`): for the current step a title and a neutral summary of 1 to 3 sentences, and optional Details with the technical facts, each derived from the request, the credential, the circuit's registry entry, the rulebook properties (`app/wallet/rulebook.ts`) and the measured metrics. It claims nothing the rulebook or the code does not. |
| Flow | Nothing is scripted. Each community has a gate `{ minAge?, maxAge? }` and the site reacts to any click order. |
| Credential | One `nym_auth` attestation covers both pseudonym and age. |
| Pseudonym config | `known-offender-matching-ssc` with `verifier_id_type: x509_san_dns`. `client_id = x509_san_dns:<siteHost>` is also the `verifier_id`. |
| Age binding | Every age request also asks for the pseudonym in the same `req`. The site accepts the age result only if the pseudonym equals the logged-in account's pseudonym. |
| 2FA | Every proof needs the device key and the wallet PIN (6 digits, default `123456`, `NUXT_WALLET_PIN`). A wrong PIN is rejected by the prover before the device key signs. |
| Unsatisfiable age | The wallet shows "Requirement Not Met" and sends `access_denied` with no description. The site cannot tell this apart from the user cancelling. |
| Errors independent of holder data | Unsupported request or no common circuit → the wallet sends `invalid_request` (rulebook allows `invalid_request` here). |
| Gate logic | The site stores the intersection of proven birth-date intervals and decides per gate: `allow`, `deny` (no overlap, so it refuses without asking the wallet), or `ask` (`shared/utils/age.ts`). |
| Ban | A ban is keyed by pseudonym. It ends the login, hides the account's comments, and blocks sign-up and age checks. |
| Offline backup | A built-in simulation of the prover and verifier (`server/utils/offline-backend.ts`) for when the addon fails. Switch in `/mod` or start with `NUXT_BACKEND_MODE=offline`. It checks the PIN and the age predicate (from the credential the wallet sends), derives the real pseudonym, sends a random proof of Vega's size (96,079 bytes), waits as long as the nym-auth-circuits benchmark says, and labels every metric simulated. No external requests at runtime. |
| Estimates | `/tech` shows per-step estimates from `shared/benchmarks.ts`. Desktop figures are measurements on Apple M5 and AMD Ryzen 9 (`NYM-AUTH.md`, `vega-caching-analysis.md`). Phone = desktop × 1–5, not measured; only phone-side steps are scaled. |

### Presentation order (not hardcoded)

1. Log in / sign up with QR, scan, consent and PIN. Optionally open the phone's "Age and pseudonym"
   card; the guide's Details then show the credential's technical facts.
2. Browse the open communities.
3. Open `c/afterdark` (18+). The wallet says "Requirement Not Met" and the site shows "Not completed".
4. Open `c/teenspace` (13–17). Access is granted. `c/afterdark` is now refused by the site itself.
5. Comment in `c/teenspace`. In the `/mod` window, ban the user. The user window shows the ban.
6. Sign up again with the same wallet. The site shows "Account banned".

`/tech` shows each step live: the request, the negotiation, the circuit, sizes and times. The guide
panel beside the site names the current step and summarises it.

## 3. Current state

```
app/
  components/WalletModal.vue     site dialog: QR, polls the server session, completes it for this browser
  components/GuidePanel.vue      the guide panel (docked right, collapsible); shows guide/steps.ts's current step
  guide/steps.ts                 the guide's steps: title, summary and details, derived from the flow state
  composables/useFlow.ts         the flow state the wallet and the dialog publish for the guide
  composables/useGuidePanel.ts   the guide's open/collapsed state and the width the site leaves for it
  components/wallet/App.vue      SIROS ID wallet: scan -> POST request_uri (wallet_metadata) -> verify JWS ->
                                 check request + select circuit -> consent -> PIN -> sign -> witness and prove ->
                                 POST response_uri
  components/wallet/*.vue        SIROS ID screens (home, credential, presentations, scan, request, PIN, progress,
                                 outcome), with the wallet's own strings
  components/wallet/THIRD-PARTY-NOTICES.txt  BSD-2-Clause (SIROS ID), ISC (lucide), OFL (Inter)
  wallet/demo-wallet.json        the holder's mdoc, device key and seed (issued by nym-issuer)
  wallet/holder.ts               the holder material and the credential decoded for the screens
  wallet/engine.ts               wallet-side rulebook checks, circuit selection, the consent model (product fields
                                 for the request screen, the technical account for the guide)
  wallet/rulebook.ts             the rulebook's properties of each pseudonym configuration
  wallet/transport.ts            HTTP transport; verifies the signed Request Object (ES256, x5c, SAN = host)
  wallet/prover.ts               the phone's native steps through /api/wallet/sign and /api/wallet/prove
  composables/useAccount.ts      account from /api/me
  pages/tech.vue                 technical view (separate window)
  pages/mod.vue                  moderation: comments, accounts, ban/unban, reset demo (separate window)
server/
  utils/services.ts              THE ONLY CODE THAT CALLS THE PROOF BACKEND (the Vega addon, or the offline simulation)
  plugins/vega.ts                builds both sides' keys when the server starts
  utils/offline-backend.ts       built-in offline simulation of prover and verifier
  utils/backend-mode.ts          native | offline, phone factor (runtime switch, /api/demo/backend)
  utils/request-signer.ts        signs Request Objects (ES256, x5c); self-signed cert unless PEMs configured
  utils/store.ts                 in-memory sessions, accounts, comments (reset with /api/demo/reset)
  utils/vp.ts                    verifier offer (config ∩ registry ∩ verifier, checked against the registry entry)
  api/vp/session.post.ts         create session → { id, authorizationUrl }
  api/vp/request/[id].ts         request_uri, GET or POST (wallet_metadata, wallet_nonce), returns signed JWT
  api/vp/response/[id].post.ts   response_uri (direct_post), calls the verifier
  api/vp/session/[id]*.ts        status polling and completion (login / age proof / ban / mismatch)
  api/wallet/*.ts                mocked phone → prover (capabilities, sign, prove)
  api/me, logout, notice, comments, mod/*, demo/reset, tech/overview
shared/
  benchmarks.ts                  timing/size model for /tech estimates and the offline simulation
  registry/circuits.ts           approved circuit registry: Vega (as the addon loads it) and Longfellow entries
  utils/mdoc.ts                  reads an IssuerSigned (wallet screens, offline simulation)
  utils/negotiation.ts           tailorFormats (verifier side), selectCircuit (wallet side)
  utils/dcql.ts                  credential query, Request Object, authorization URL (request_uri_method=post)
  utils/pseudonym.ts             pseudonym-v1-sha256, all four configs
  types/oid4vp.ts                protocol types
native/vega/                     Rust workspace: the proof backend
  vega-age/, circuits/           nym-auth-circuits circuits and shapes, vendored unchanged (VENDOR-SHA256SUMS)
  nym-vega/                      prover steps and verifier around vega-age (OpenID4VP handover, presentation, checks)
  node/                          the napi-rs addon (Prover, Verifier)
  issuer/                        nym-issuer: the demo credential, keys and trust anchor
  demo/document-signer.pem       the verifier's trust anchor
Dockerfile                       the site with the addon (Rust build stage); docker-compose.yml runs it
docker-compose.longfellow.yml    kept from the HTTP design; has no effect on the addon-based site
scripts/build-native.mjs         npm run build:native
scripts/vega-check.mjs           npm run vega:check: real proofs, pseudonym, refusals
scripts/demo-flow.mjs            headless run of the presentation order: guide steps, phone traffic, screenshots
```

All of the flow is real: the OpenID4VP request/response, signed Request Objects, capability
negotiation, DCQL `circuit_zk` checks on both sides, the CBOR presentation encoding, the pseudonym
derivation, the PIN check, the Vega proof and its verification, accounts, bans and gate logic. What
is not: the holder binding (the device key and the seed sit in the page) and the phone's speed
(proofs run on the server's CPU).

## 4. What needs to be done

1. **Confirm the registry values** in `shared/registry/circuits.ts` with Peter: circuit ids, proof
   system ids, and the public-input order. The Vega entry matches what the addon loads (the site
   checks the id, the proof system, the public-input order and the `shapes.zst` hash at runtime).
2. **Optional: a configured request-signing certificate** (`NUXT_REQUEST_SIGNING_KEY` and
   `NUXT_REQUEST_SIGNING_CERT`). The leaf needs dNSName SAN = `siteHost`. The mocked wallet does not
   check the trust chain.
3. **Projector check.** The dialog is about 745 px tall, and the guide panel takes 352 px at the right
   edge (44 px when collapsed). Test at the venue resolution.
4. **Longfellow.** The HTTP override (`docker-compose.longfellow.yml`) no longer reaches the site. A
   Longfellow backend would plug into `server/utils/services.ts` beside the Vega addon.

## 5. Rules for changing the code

- Keep the UI and copy as they are unless asked. They have been reviewed.
- Only `server/utils/services.ts` calls the proof backend (the Vega addon). Keep it that way.
- The site must take `request` and `handover` from its own session store when verifying, never
  from the wallet's response.
- Do not add protocol details to Readdit or the wallet screens. They go in the guide panel's Details,
  derived from the flow state (`app/guide/steps.ts`).
- Do not hardcode the demo order or the persona's age in site logic.
- Shared logic goes in `shared/`, imported as `#shared/...`.
- `@peculiar/x509` needs `reflect-metadata` loaded first. Import both dynamically, as
  `request-signer.ts` and `wallet/transport.ts` do; static imports get reordered or tree-shaken.

## 6. Running and testing

See `GETTING-STARTED.md` for starting the demo and using the three views. Short version:

```sh
npm install
npm run build:native          # the Vega addon (Rust); again after changing native/vega
npm run dev                   # http://localhost:3000
# in a container: docker compose up -d --build
# separate windows: /tech  /mod (also linked from the guide panel's footer)
```

Checks, after every change:

```sh
npx nuxi typecheck                                  # needs: npm i --no-save typescript@5 vue-tsc
node scripts/demo-flow.mjs http://localhost:3000    # needs: npm i --no-save playwright && npx playwright install chromium
npm run vega:check                                  # after changing native/vega
(cd native/vega && cargo test -p nym-vega)
```

`scripts/demo-flow.mjs` runs the presentation order headlessly against the running site, including
the wrong PIN, the ban and the second sign-up. At each step it checks that the guide panel shows the
matching step, and it saves a viewport screenshot of the page: Readdit, the phone in the dialog and
the guide (`node scripts/demo-flow.mjs <base> <dir>`; the PR's set is in
`docs/screenshots/vega-siros-wallet/`).
