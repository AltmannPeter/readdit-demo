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
server builds it. There is no true holder binding: the mocked wallet carries its two credentials,
their device keys and seeds outright (`app/wallet/demo-wallet.json`) and sends what each native step
needs from the credential the person chose; the prover keeps none of it.

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
| Guide | **Added 2026-10-13 (Frédéric):** a guide panel docked at the right edge, styled apart from the product, collapsible. It follows the flow state by itself (`app/guide/steps.ts`): for the current step a title and a neutral summary of 1 to 3 sentences, and optional Details with the technical facts, each derived from the request, the credential, the circuit's registry entry, the rulebook properties (`app/wallet/rulebook.ts`) and the measured metrics (the prover's and, apart, the verifier's). It claims nothing the rulebook or the code does not. **Added 2026-10-13 (Peter):** after a success the site dialog stays open until Close on the phone's success screen (no automatic close). The presenter can step back and forward through the steps shown so far (‹ › in the guide header, up to 50); any new step jumps back to the present. |
| Flow | Nothing is scripted. Each community has a gate `{ minAge?, maxAge? }` and the site reacts to any click order. |
| Credential | **Changed 2026-10-13 (Frédéric):** the wallet holds two `nym_auth` credentials from one Document Signer: the teen's (born 2011-03-14) and an adult's (born 1990-05-20); a request starts with the credential shown on the wallet's home screen (or opened last), the teen's until another is chosen. Each covers both pseudonym and age, with its own seed, so each gives its own pseudonym and account. Each card has its own colour (teen grey `#5B6573`, adult red `#8C2F39`; the request screen's credential header takes the same colour, and the Share button stays SIROS blue, `CARD_COLOURS` in `app/wallet/holder.ts`) and shows the holder's birth date ("Birth Date"), which tell them apart. The Personal ID placeholder card was removed on 2026-10-13 (Peter); the birth date stays on the phone. The request screen does not show the birth date (it is not shared): it lists one tile per shared item, the pseudonym and, when asked, the age range or threshold ("Age proof"). They do not expire: validUntil `9999-12-31T23:59:59Z` and the Document Signer's notAfter `99991231235959Z`; the product shows no expiry. When both match a request, the request screen offers "Switch credential", as the SIROS ID app does. Was: "One `nym_auth` attestation covers both pseudonym and age." |
| Pseudonym config | `known-offender-matching-ssc` with `verifier_id_type: x509_san_dns`. `client_id = x509_san_dns:<siteHost>` is also the `verifier_id`. |
| Age binding | Every age request also asks for the pseudonym in the same `req`. The site accepts the age result only if the pseudonym equals the logged-in account's pseudonym. |
| Logged-out gated community | **Changed 2026-10-13 (Frédéric's report "the after dark is locked without having verified the age"):** a logged-out visitor at an age-restricted community sees its age requirement and one button, which starts one request for the pseudonym and the age range: it creates the account or logs in to it, and records the age. Plain log-in and sign-up still ask for the pseudonym only. Was: "Log in to view" with a lock, then a second request for the age. |
| 2FA | **Replaced 2026-10-13 (Frédéric):** any PIN unlocks the device key. The PIN screen stays as the phone's unlock (the SIROS ID app unlocks with a passkey); no PIN reaches the server, and the prover takes none. Was: every proof needed the device key and the wallet PIN (6 digits, set by `NUXT_WALLET_PIN`), and the prover refused a wrong PIN before the device key signed. |
| Unsatisfiable age | The wallet shows "Requirement Not Met" and sends `access_denied` with no description. The site cannot tell this apart from the user cancelling. |
| Errors independent of holder data | Unsupported request or no common circuit → the wallet sends `invalid_request` (rulebook allows `invalid_request` here). |
| Gate logic | The site stores the intersection of proven birth-date intervals and decides per gate: `allow`, `deny` (no overlap, so it refuses without asking the wallet), or `ask` (`shared/utils/age.ts`). |
| Ban | A ban is keyed by pseudonym. It ends the login, hides the account's comments, and blocks sign-up and age checks. |
| Offline backup | **Removed 2026-10-13 (Frédéric):** there is no fallback backend. The Vega addon is built into the site's server; when it cannot load, the built site refuses to start and says to run `npm run build:native`. A failing prove or verify call is the "backend unavailable" path (500 `backend_error` or 503 `unavailable`). Was: "A built-in simulation of the prover and verifier (`server/utils/offline-backend.ts`) for when the addon fails. Switch in `/mod` or start with `NUXT_BACKEND_MODE=offline`. …" |
| Sign-up and log-in | **Changed 2026-10-13, while handling every flow (Frédéric's request):** both send the same wallet request. Sign-up creates the account; **changed 2026-10-13 (Peter):** when the pseudonym already has an account, sign-up logs nothing in, and the dialog says "Account already exists" and offers Log in (a sign-up for an age-restricted community still logs in to the existing account); log-in only logs in, and with no account answers "No account" and offers Sign up, creating nothing. Was: the same request created the account or logged in to it, whatever the button; the button only set the dialog's title. |
| Refusals | A refusal names its code in the error body (`data.error`); docs/backend-api.md lists them per route. response_uri answers 200 once a response is processed, accepted or refused; the rule of a refused presentation goes to the server log and the session trace, not to the caller. Closing the site's dialog cancels the session, so a later answer is refused with 410. |
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
                                 outcome, Switch credential), with the wallet's own strings
  components/wallet/THIRD-PARTY-NOTICES.txt  BSD-2-Clause (SIROS ID), ISC (lucide), OFL (Inter)
  wallet/demo-wallet.json        two holders' mdocs, device keys and seeds (issued by nym-issuer under one signer)
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
  utils/services.ts              THE ONLY CODE THAT CALLS THE PROOF BACKEND (the Vega addon)
  plugins/vega.ts                builds both sides' keys when the server starts; stops the built server without the addon
  utils/test-faults.ts           test only (READDIT_TEST_FAULTS=1): fails the next call of one addon step
  utils/errors.ts                refusals with a code in data.error; body parsing
  utils/request-signer.ts        signs Request Objects (ES256, x5c); self-signed cert unless PEMs configured
  utils/store.ts                 in-memory sessions, accounts, comments (reset with /api/demo/reset)
  utils/vp.ts                    verifier offer (config ∩ registry ∩ verifier, checked against the registry entry)
  api/vp/session.post.ts         create session → { id, authorizationUrl }
  api/vp/request/[id].ts         request_uri, GET or POST (wallet_metadata, wallet_nonce), returns signed JWT
  api/vp/response/[id].post.ts   response_uri (direct_post), calls the verifier
  api/vp/session/[id]*.ts        status polling, completion (login / no account / age proof / ban / mismatch), cancel
  api/test/fault.post.ts         test only (READDIT_TEST_FAULTS=1), 404 otherwise
  api/wallet/*.ts                mocked phone → prover (capabilities, sign, prove)
  api/me, logout, notice, comments, mod/*, demo/reset, tech/overview
shared/
  benchmarks.ts                  timing/size model for /tech estimates
  registry/circuits.ts           approved circuit registry: Vega (as the addon loads it) and Longfellow entries
  utils/mdoc.ts                  reads an IssuerSigned (wallet screens)
  utils/negotiation.ts           tailorFormats (verifier side), selectCircuit (wallet side)
  utils/dcql.ts                  credential query, Request Object, authorization URL (request_uri_method=post)
  utils/pseudonym.ts             pseudonym-v1-sha256, all four configs
  types/oid4vp.ts                protocol types
native/vega/                     Rust workspace: the proof backend
  vega-age/, circuits/           nym-auth-circuits circuits and shapes, vendored unchanged (VENDOR-SHA256SUMS)
  nym-vega/                      prover steps and verifier around vega-age (OpenID4VP handover, presentation, checks)
  node/                          the napi-rs addon (Prover, Verifier)
  issuer/                        nym-issuer: the demo credentials (one per --holder), keys and trust anchor
  demo/document-signer.pem       the verifier's trust anchor
Dockerfile                       the site with the addon (Rust build stage); docker-compose.yml runs it
.devcontainer/devcontainer.json  GitHub Codespaces: builds the Dockerfile and runs the site on port 3000 (TRY-IT.md)
docker-compose.longfellow.yml    kept from the HTTP design; has no effect on the addon-based site
scripts/build-native.mjs         npm run build:native
scripts/vega-check.mjs           npm run vega:check: real proofs, pseudonym, refusals
scripts/demo-flow.mjs            headless run of the presentation order: guide steps, phone traffic, screenshots
scripts/flows-check.mjs          every flow, happy and unhappy, in the browser and over HTTP; screenshots 19-29
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
node scripts/flows-check.mjs http://localhost:3000  # every flow; start the built server as GETTING-STARTED, "Checks", says
npm run vega:check                                  # after changing native/vega
(cd native/vega && cargo test -p nym-vega)
```

`scripts/demo-flow.mjs` runs the presentation order headlessly against the running site, including
the ban and the second sign-up, with a different PIN at each unlock. At each step it checks that the guide panel shows the
matching step, and it saves a viewport screenshot of the page: Readdit, the phone in the dialog and
the guide (`node scripts/demo-flow.mjs <base> <dir>`; the PR's set is in
`docs/screenshots/vega-siros-wallet/`).

`scripts/flows-check.mjs` drives every flow of the inventory (the PR lists them): sign-up, log-in
and log-out, the communities and age gates, the one request at a gated community when logged out,
comments, bans, both credentials and Switch credential, the wallet's refusals (decline, cancel at
the PIN, requirement not met, unsupported and untrusted requests), closing the dialog, expired and
used QR codes, an age proof from the other credential, a ban or a log-out during a request, a demo
reset, and over HTTP the verifier's refusals (replay, another state or nonce, tampered
presentations, malformed bodies, another browser) and the backend failing through the test-only
hook. It checks the product, the guide step (with the verifier's measured times after each
verified presentation) and every server answer, and that nothing carries over into the next path.
It needs the built server with `NUXT_VP_SESSION_TTL_S=40` and `READDIT_TEST_FAULTS=1`
(GETTING-STARTED, "Checks").
