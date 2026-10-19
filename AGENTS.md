# Agent guide: Readdit pseudonym and age demo

Read this before changing anything. It records the decisions so far, the current state, and what
is left. The owner is Peter Altmann (SIROS Foundation). He knows the cryptography in depth and will
check protocol claims, so cite the rulebook section when you rely on it.

## 1. What this is

A Reddit-style demo site, **Readdit**, for a 15-minute talk to a non-technical audience. The talk
has to show two things:

- Pseudonymous presentations from the EU Digital Identity Wallet are a workable alternative to
  presenting identity data.
- A real zero-knowledge implementation runs behind the demo: Vega (Microsoft vega-prover) and
  Longfellow (Google longfellow-zk, Rust) with the nym_auth circuits of the nym-auth-circuits
  archive, over the same mdoc (see section 2), and, next to them, BBS with committed disclosures
  (sirosfoundation/bbs-cd-plugins) for a BBS form of the same credential (the `mms_zk` format,
  `docs/mms_zk.md`).

The person uses Readdit on a computer and an identity wallet on their phone for every identity step,
over cross-device OpenID4VP (QR code).

- **Sign up and log in** with a pseudonym derived from the `eu.europa.ec.eudi.nym_auth.1`
  attestation. The pseudonym is the account identifier. There is no email, password or name.
- **Age-gated communities.** `c/teenspace` requires 13–17 and `c/afterdark` requires 18+.
- **Communities with their own pseudonym.** `c/france` wants proof of a real person, against bot
  accounts: it asks for a pseudonym under its own verifier identity (`france.readdit.example`), so
  each person gets one `c/france` account, not linked to their Readdit account unless they choose to.
- **Two phones.** The teen's phone (the teen's mdoc and the teen's BBS credential) and the adult's
  phone (the adult's mdoc). Swapping phones at the QR code shows someone trying another person's phone.
- **Which proofs the site accepts.** `/tech` switches the proof systems Readdit accepts: Vega and
  Longfellow (`circuit_zk`) and BBS (`mms_zk`); none at start. With BBS and a `circuit_zk` system,
  the request offers both formats as alternatives and the wallet answers with one.
- **Ban.** A moderator bans the account. The same wallet always yields the same pseudonym for
  Readdit, so signing up again lands on the banned account (known-offender matching within one site).
- **Interfaces are mocked, transactions are real.** The site and phone UIs are mocked. The OpenID4VP
  request and response, proof generation and proof verification are real. The last two run in the
  site's server, in Rust Node addons (`native/vega`, `native/longfellow`, `native/bbs`).

The phone on screen is part of the website UI. It plays a person's wallet, the SIROS ID wallet.
In the real world the wallet would build the proof on the phone. Here the provers in the site's
server build it. There is no true holder binding: the mocked wallets carry their credentials,
their device keys and seeds outright (`app/wallet/demo-wallet.json`, `demo-wallet-bbs.json`) and send what each native step
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
| Stack | Nuxt 4, TypeScript, Tailwind v4, Nitro server routes. Node `^22.22.3` or `>=24.15`. Rust (stable) for the proof addons. |
| Backend | **Replaced 2026-10-13 (Frédéric):** the prover and verifier are a Rust Node addon (napi-rs, `native/vega`) that the site's server loads; `server/utils/services.ts` is the only caller. Two separate objects, each building its keys once at start. The contract is in `docs/backend-api.md`. Was: "Prover and verifier run as local containers. The demo uses Longfellow." **Added 2026-10-19 (Peter):** a second addon, `native/bbs`, for BBS (row BBS), and a third, `native/longfellow` (row Longfellow). The site starts when at least one addon loads (`server/plugins/backends.ts`). |
| BBS | **Added 2026-10-19 (Peter):** the real BBS cryptography, not a mock: sirosfoundation/bbs-cd-plugins 0.1 (ETSI BBS committed disclosures v0.7, BLS12-381-SHA-256) vendored unchanged in `native/bbs/vendor` (`native/bbs/VENDOR-SHA256SUMS`), with the plugins `ecdsa-pop` (hashed mode: device binding, decided), `pseudonym` and `date-range`. The demo profile is `docs/mms_zk.md` (`native/bbs/nym-bbs`). A new DCQL format `mms_zk` (Peter's name), its own function `pseudonym-bbs-v1` with the configuration as a parameter (`known-offender-matching-ssc`, `x509_san_dns`), and `age_check` as in the rulebook. The pseudonym is SHA-256 of the plugin's G1 point (Peter), so it is 32 bytes like the Vega one, but never equal to it: one person has one account per format. The BBS credential (`app/wallet/demo-wallet-bbs.json`, `native/bbs/issuer`) is the teen's only, with the teen's mdoc device key. |
| Accepted proof systems | **Added 2026-10-19 (Peter):** the site decides which formats it accepts and says so in the request (`vp_formats_supported`, and the DCQL query). Switches in `/tech` (`POST /api/tech/accept`), default Vega only; a demo reset restores the default (`NUXT_ACCEPTED_PROOF_SYSTEMS`). **Fixed 2026-10-19 (Peter's report: with BBS only, an mdoc presentation still went through):** the offer and the DCQL query are made again when the wallet fetches the request (request_uri), so a QR code already on screen follows the switches, and response_uri refuses a presentation whose format is no longer accepted (code `format`). With both, the query holds the `circuit_zk` and the `mms_zk` credential query, `circuit_zk` first, as alternatives in one `credential_sets` entry; the wallet answers with the selected card if it fits, else the first that does, and offers "Switch credential". A person banned under one format can come back under the other when the site accepts both: that is the site's choice. **Changed 2026-10-19 (Peter):** nothing is accepted at start or after a demo reset (`NUXT_ACCEPTED_PROOF_SYSTEMS` empty); the operator switches proof systems on in `/tech`. Until then the site starts no wallet request (503 `none_accepted`): the dialog says "No proof accepted", the guide says what to tick, `/tech` says so above the switches. Switching the last one off is allowed. Vega and Longfellow are switched separately, though both are `circuit_zk`: the request lists the accepted circuits, and response_uri also refuses a presentation whose circuit's proof system was switched off meanwhile (code `format`). |
| Proof system | **Replaced 2026-10-13 (Frédéric):** Vega (`vega-v1`, microsoft/vega-prover `c0ee259`) with the nym-auth-circuits `vega-age` circuits, vendored unchanged, circuit `urn:circuits:vega:nym_auth:v1`. The full `circuit_zk` DCQL extension is implemented, including capability negotiation. Was: "Longfellow for the demo." Longfellow is the second `circuit_zk` backend (row Longfellow). |
| Longfellow | **Decided 2026-10-13 (Peter):** Longfellow is added next to Vega, not instead of it. Implementation: Google's Rust Longfellow (the "Google Rust" runtime of `NYM-AUTH.md`). The nym_auth circuit is generated by Peter's team (the reference macro, `macros/longfellow/nym-auth.macro` in his workspace). The site starts when at least one backend loads, and offers only the circuits of the backends that loaded. **Built 2026-10-19 (Peter):** from the nym-auth-circuits archive's Longfellow part instead of a macro build: `longfellow/mdoc`, the LFC2 pair (hash circuit over GF(2^128), signature circuit over P-256, SPEC.md L1–L9), on Google's longfellow-zk Rust runtime `61a8a73`, its 11 runtime crates vendored unchanged in `native/longfellow/vendor/longfellow-zk` (Peter: vendored, not fetched; the trimmed workspace manifest there is ours; `native/longfellow/VENDOR-SHA256SUMS`). mdoc only (Peter): the archive's SD-JWT circuits are not used. Circuit `urn:circuits:longfellow:nym_auth:v1`, proof system `longfellow-libzk-v1`, the same credential, DeviceAuthentication and pseudonym function as Vega, so a person has one account under either. Preference Vega, then Longfellow (Peter). The archive's fixtures use the DC API handover; Readdit uses B.2.6.1. The circuits take e2 as a public input and the SessionTranscript only seeds Fiat–Shamir, so nothing in them changes (`native/longfellow/nym-longfellow/src/lib.rs`). The seed question is settled: the circuits prove `ssc = SHA-256(secret_seed)` with the seed held by the wallet. |
| Brand | Site name "Readdit", lowercase wordmark "readdit", original logo. Communities are prefixed `c/`. Do not use Reddit's logo, mascot or `r/`. |
| Wallet look | **Replaced 2026-10-13 (Frédéric):** the SIROS ID wallet (sirosfoundation/wallet-frontend, BSD-2-Clause): its screens, colours (`--color-sid-*`), Inter, lucide icons and logo, attributed in `app/components/wallet/THIRD-PARTY-NOTICES.txt`. The phone frame stays generic. The site's dialog names no wallet brand: its steps say "Open an EUDI Wallet App on your phone"; sign-up and log-in have no subtitle (Peter, 2026-10-13). Was: "Generic phone with no brand marks. App name 'EUDI Wallet App', grey-blue palette, no logo." |
| Consent | **Replaced 2026-10-13 (Frédéric):** the wallet's request screen is the SIROS ID one: the requester (name and domain) and the requested information in product wording, derived from the request: a pseudonym specific to the site and, only when asked, the age range computed from the request's bounds. **Changed 2026-10-19 (Peter), after SIROS ID's newer design:** the requester's domain only (no name), no credential header bar, and one card per requested item, age proof first: an icon tile (lucide `calendar-check` for the age proof, `hat-glasses` for the pseudonym) and the title. "Age proof: 13–17" (or "18+", "under 18") has nothing else. "Pseudonym" has "Specific to <host>", then a divider and its properties as a dash list, each on one line: "Your personal data will not be shared", "You cannot be tracked across sites" (by `distinctPerVerifier`), "The site can recognize your account", "The issuer may be able to reveal your identity" (by `issuerCanLink`; "may", because the issuer may not keep the mapping). No "Derived from PID" line: the credential is the nym_auth attestation. The birth date is not shown on this screen. The technical account of the same request (the pseudonym and the rulebook's properties of its configuration, what is not shared, the other values the verifier receives, `client_id` and the signing certificate) is in the guide panel's Details. All of it comes from `consentFor` (`app/wallet/engine.ts`). Was: "The wallet's request screen shows what the request actually discloses: the verifier (name, host, `client_id`, signing certificate), the pseudonym the wallet computes for this site with the rulebook's properties, the age range if asked, the other public inputs, and what is not shared." |
| Audience | **Replaced 2026-10-13 (Frédéric):** the main window shows the product (Readdit and the SIROS ID wallet) with product copy only, and the guide panel beside it. Technical detail lives in the guide's Details and in the operator pages `/tech` and `/mod`. The credential window `/wallet/credential` is gone. Was: "Technical detail lives only in separate windows: `/tech`, `/mod`, and the credential window `/wallet/credential`." |
| Copy | Tight and plain. It must not sound like marketing or AI-written text. The wallet uses the SIROS ID wallet's English strings (`src/locales/en.json`) wherever one exists; screens the real wallet lacks ("Requirement Not Met") are written in the same style. |
| Guide | **Added 2026-10-13 (Frédéric):** a guide panel docked at the right edge, styled apart from the product, collapsible. It follows the flow state by itself (`app/guide/steps.ts`): for the current step a title and a neutral summary of 1 to 3 sentences, and optional Details with the technical facts, each derived from the request, the credential, the circuit's registry entry, the rulebook properties (`app/wallet/rulebook.ts`) and the measured metrics (the prover's and, apart, the verifier's). It claims nothing the rulebook or the code does not. **Added 2026-10-13 (Peter):** the presenter can step back and forward through the steps shown so far (‹ › in the guide header, up to 50); any new step jumps back to the present. |
| Flow | Nothing is scripted. Each community has a gate `{ minAge?, maxAge? }` and the site reacts to any click order. |
| Phones | **Added 2026-10-19 (Peter):** two phones, one person each (`PHONES` in `app/wallet/holder.ts`): "Teen's phone" holds the teen's mdoc and the teen's BBS credential (card "Age and pseudonym (BBS)", teal `#2E5E6E`), "Adult's phone" the adult's mdoc. The card chosen with Switch credential becomes the phone's selected card, so the next request starts with it (a page reload starts again with the first card). The dialog shows one at a time, named above it with the owner's age from the credential ("Teen's phone · 15"), in a frame colour per phone (grey, red), with **Swap phone**, which works until the phone on screen has scanned. The choice stays across dialogs until swapped (a page reload starts on the teen's phone). Each phone keeps its own history and selected card. The site records a swap in the session (`POST /api/vp/session/:id/phone`) for `/tech`; the guide names the phone in every step's context and says when the phones were swapped. The cheating attempt: logged in as the teen, swap to the adult's phone at c/afterdark's QR code; it proves 18+, and Readdit answers "Pseudonym does not match". |
| Credential | **Changed 2026-10-13 (Frédéric), split over two phones 2026-10-19 (Peter):** two `nym_auth` credentials from one Document Signer: the teen's (born 2011-03-14) and an adult's (born 1990-05-20), one per phone; a request starts with the credential shown on the phone's home screen (or opened last). Each covers both pseudonym and age, with its own seed, so each gives its own pseudonym and account. Each card has its own colour (teen grey `#5B6573`, adult red `#8C2F39`, `CARD_COLOURS` in `app/wallet/holder.ts`) and shows the holder's birth date ("Birth Date"), which tell them apart. The birth date stays on the phone; the request screen does not show it. The wallet holds no other card (the Personal ID placeholder was removed on 2026-10-13, Peter). They do not expire: validUntil `9999-12-31T23:59:59Z` and the Document Signer's notAfter `99991231235959Z`; the product shows no expiry. When more than one credential on a phone matches a request, the request screen offers "Switch credential", as the SIROS ID app does; with one credential per phone it does not appear. Was: "One `nym_auth` attestation covers both pseudonym and age." |
| Pseudonym config | `known-offender-matching-ssc` with `verifier_id_type: x509_san_dns`. `client_id = x509_san_dns:<siteHost>` is also the `verifier_id`; a community with its own pseudonym uses `x509_san_dns:<nymHost>` instead. |
| Own-pseudonym communities | **Added 2026-10-19 (Peter):** a community can set `nymHost` (`shared/data/communities.ts`); c/france uses `france.readdit.example`. Its requests carry `client_id = x509_san_dns:<nymHost>`, and the request-signing certificate lists that name too (`verifierHosts`). The Vega circuit takes `verifier_input` = SHA-256(client_id) as a public input, so the same credential gives a different, unlinkable pseudonym there, with no circuit change (the circuit fixes the DST, `prover_input` = zeros and `ssc`; it cannot do a user-chosen input or `psc`). One account per person, known-offender matching within c/france, bans stick. The issuer can still link (ssc); the ideal is `private_seed` (psc), which needs a new circuit. Rules: c/france posts and comments are visible only with a c/france account, and appear under its pseudonym only. Logged out, joining creates or opens a standalone c/france account. Logged in to Readdit, only the c/france account linked to that account counts. Without one, the person chooses (Peter, 2026-10-19; no extra confirm step): **Join and link to u/…** (creates the c/france account or links a standalone one), or **Log out and join separately** (no link). The server refuses a logged-in join that does not say `link: true` (`400 link_required`). Linking refused as `other_pseudonym` when the Readdit account is already linked to another c/france pseudonym (another person's wallet), and as `linked_elsewhere` when the c/france account is linked to another Readdit account. A Readdit account cannot be added from a c/france-only login. A ban in c/france applies to the c/france pseudonym only. A ban of a Readdit account also bans the community accounts linked to it (`banned.cascade`); unbanning the Readdit account lifts those, not a community account's own ban (Peter, 2026-10-19). Age ranges live on the Readdit account only, so a linked c/france account from another phone opens no age-gated community. Accounts of both kinds share one store, keyed by pseudonym; `community` and `linkedTo` mark community accounts. Badge and notice: "Proof of human"; copy says the c/france pseudonym is not linked to other accounts "unless you choose to" (Peter, 2026-10-19). With only a c/france account, the header shows it like a Readdit account, marked with the community, and its menu offers Log in to Readdit and Log out. |
| Age binding | Every age request also asks for the pseudonym in the same `req`. The site accepts the age result only if the pseudonym equals the logged-in account's pseudonym; otherwise the dialog says "Pseudonym does not match" and nothing is applied (for example an adult credential's proof while logged in with the teen's account). |
| Logged-out gated community | **Changed 2026-10-13 (Frédéric's report "the after dark is locked without having verified the age"):** a logged-out visitor at an age-restricted community sees its age requirement and one button, which starts one request for the pseudonym and the age range: it creates the account or logs in to it, and records the age. Plain log-in and sign-up still ask for the pseudonym only. Was: "Log in to view" with a lock, then a second request for the age. |
| Logged-out pages | **Added 2026-10-13 (Peter):** the home feed and the open communities show no posts when logged out. They show one notice (`app/components/LoginNotice.vue`) with three short paragraphs (pseudonym and no personal information, age-limited communities, accounts bound to an identity attestation so no bot accounts) and Sign up / Log in. Age-restricted communities keep their age notice (row above). Sign up is an outline button and Log in a filled one, everywhere. |
| Dialog | **Added 2026-10-13 (Peter):** after a success the site dialog stays open until Close on the phone's success screen; there is no automatic close. The site's own close (×, Esc, backdrop) still works. The PIN screen's buttons and the outcome screens are centred. |
| 2FA | **Replaced 2026-10-13 (Frédéric):** any PIN unlocks the device key. The PIN screen stays as the phone's unlock (the SIROS ID app unlocks with a passkey); no PIN reaches the server, and the prover takes none. Was: every proof needed the device key and the wallet PIN (6 digits, set by `NUXT_WALLET_PIN`), and the prover refused a wrong PIN before the device key signed. |
| Unsatisfiable age | The wallet shows "Requirement Not Met" and sends `access_denied` with no description. The site cannot tell this apart from the user cancelling. |
| Errors independent of holder data | Unsupported request or no common circuit → the wallet sends `invalid_request` (rulebook allows `invalid_request` here). |
| Gate logic | The site stores the intersection of proven birth-date intervals and decides per gate: `allow`, `deny` (no overlap, so it refuses without asking the wallet), or `ask` (`shared/utils/age.ts`). |
| Ban | A ban is keyed by pseudonym. It ends the login, hides the account's comments, and blocks sign-up and age checks. |
| Offline backup | **Removed 2026-10-13 (Frédéric):** there is no fallback backend. The Vega addon is built into the site's server; when it cannot load, the built site refuses to start and says to run `npm run build:native`. A failing prove or verify call is the "backend unavailable" path (500 `backend_error` or 503 `unavailable`). Was: "A built-in simulation of the prover and verifier (`server/utils/offline-backend.ts`) for when the addon fails. Switch in `/mod` or start with `NUXT_BACKEND_MODE=offline`. …" |
| Sign-up and log-in | **Changed 2026-10-13, while handling every flow (Frédéric's request):** both send the same wallet request. Sign-up creates the account; **changed 2026-10-13 (Peter):** when the pseudonym already has an account, sign-up logs nothing in, and the dialog says "Account already exists" and offers Log in (a sign-up for an age-restricted community still logs in to the existing account); log-in only logs in, and with no account answers "No account" and offers Sign up, creating nothing. Was: the same request created the account or logged in to it, whatever the button; the button only set the dialog's title. |
| Refusals | A refusal names its code in the error body (`data.error`); docs/backend-api.md lists them per route. response_uri answers 200 once a response is processed, accepted or refused; the rule of a refused presentation goes to the server log and the session trace, not to the caller. Closing the site's dialog cancels the session, so a later answer is refused with 410. |
| Measurements | **Replaced 2026-10-19 (Peter: "the estimates add nothing now"):** `/tech` shows the real runs instead: every presentation proved through the mocked phone and verified is appended to `.data/measurements.jsonl` (`NUXT_MEASUREMENTS_FILE`; kept across restarts and demo resets, Peter: saved to disk; a Docker volume keeps it across rebuilds) and grouped by proof system, statement (pseudonym, or pseudonym and age), prover threads and machine: runs, prove and verify time (median and range), proof and presentation size, peak memory of the server process. Prove = the phone's work (device signature, witness, proof; BBS: the whole presentation) on the server's CPU. **Clear** (two clicks) empties the file. `server/utils/measurements.ts`. Was: per-step estimates from `shared/benchmarks.ts` (published desktop figures, phone = desktop × 1–5). |
| Threads | **Added 2026-10-19 (Peter):** a switch in `/tech`, "Multithreading (Vega and BBS)". Off (the start state, and after a demo reset; `NUXT_MULTITHREADING`): Vega and BBS run on one thread. On: on one thread per core, and `/tech` says how many. Vega runs each step inside a rayon pool of 1 or all cores (`native/vega/nym-vega/src/threads.rs`); BBS is built with bbs-cd-plugins' `parallel` feature and takes `Parallelism::Off` or `Max` per call (output identical, by the library's design). Longfellow stays on one thread: Google's runtime `61a8a73` has no parallel code, and it stays vendored unchanged (Peter). The services pass the switch per call (`parallel` in the JSON); the metrics, the traces and the measurements record the threads used. |
| Hosting | **Added 2026-10-13 (Peter):** people try the demo in GitHub Codespaces (`.devcontainer/`, `TRY-IT.md`, README button): each visitor gets their own copy, built from the Dockerfile. No shared public site, so no per-visitor wallets or `/mod` password are needed. Behind the Codespaces proxy the server cannot see its public address, so the page sends `location.origin` when it creates a session and request_uri and response_uri use it (`server/api/vp/session.post.ts`, `publicOrigin`). |

### Presentation order (not hardcoded)

1. Sign up on the teen's phone with QR, scan, consent and PIN. Optionally open the phone's "Age and
   pseudonym" card; the guide's Details then show the credential's technical facts.
2. Browse the open communities.
3. Open `c/afterdark` (18+). The wallet says "Requirement Not Met" and the site shows "Not completed".
   **Try again**, then **Swap phone** to the adult's phone at the QR code: it proves 18+, and the site
   rejects it ("Pseudonym does not match").
4. Open `c/teenspace` (13–17) on the teen's phone. Access is granted. `c/afterdark` is now refused by
   the site itself.
5. Open `c/france`, **Join and link** with the teen's phone: a c/france pseudonym, linked to the account.
6. Comment in `c/teenspace`. In the `/mod` window, ban the user. The user window shows the ban.
7. Sign up again with the same wallet. The site shows "Account banned".
8. BBS: reset the demo, and in `/tech` accept BBS (alone, or with Vega to show the choice). Sign up on
   the teen's phone with the BBS card, then `c/teenspace`: the age range comes from the date-range
   plugin, and `c/afterdark` is refused by the site.
9. Longfellow: reset the demo, accept Longfellow in `/tech`. Sign up on the teen's phone, try
   `c/afterdark` (Requirement Not Met), then `c/teenspace`.

Before step 1, the operator ticks Vega in `/tech`: nothing is accepted at start.

`/tech` shows each step live: the request, the negotiation, the circuit, sizes and times. The guide
panel beside the site names the current step and summarises it.

## 3. Current state

```
app/
  components/WalletModal.vue     site dialog: QR, polls the server session, completes it for this browser
  components/LoginNotice.vue     logged-out notice on the home feed and the open communities
  components/GateNotice.vue      a community's gate: log-in notice, age notice, refused, join (own pseudonym), banned there
  components/HumanBadge.vue      "Proof of human", for communities with their own pseudonym
  components/UserMenu.vue        the header's account: Readdit, or a community-only account marked with its community
  composables/usePhone.ts        the demo phone on screen and Swap phone
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
  wallet/demo-wallet-bbs.json    the teen's BBS credential and device key (issued by bbs-issuer)
                                 (holder.ts PHONES: which phone holds which)
  wallet/holder.ts               the holder material and the credential decoded for the screens
  wallet/engine.ts               wallet-side rulebook checks, circuit selection, the consent model (product fields
                                 for the request screen, the technical account for the guide)
  wallet/rulebook.ts             the rulebook's properties of each pseudonym configuration
  wallet/transport.ts            HTTP transport; verifies the signed Request Object (ES256, x5c, SAN = host)
  wallet/prover.ts               the phone's native steps through /api/wallet/sign and /api/wallet/prove (BBS: prove only)
  composables/useAccount.ts      account from /api/me
  pages/tech.vue                 technical view (separate window)
  pages/mod.vue                  moderation: comments, accounts (linked community accounts under their Readdit
                                 account, components/ModAccount.vue), ban/unban, reset demo (separate window)
server/
  utils/services.ts              THE ONLY CODE THAT CALLS THE PROOF BACKENDS (the Vega, Longfellow and BBS addons;
                                 circuit_zk calls go to the addon of the circuit)
  plugins/backends.ts            loads the three addons when the server starts; stops the built server when none loads
  utils/test-faults.ts           test only (READDIT_TEST_FAULTS=1): fails the next call of one addon step
  utils/errors.ts                refusals with a code in data.error; body parsing
  utils/request-signer.ts        signs Request Objects (ES256, x5c); self-signed cert unless PEMs configured
  utils/store.ts                 in-memory sessions, accounts, comments (reset with /api/demo/reset)
  utils/vp.ts                    verifier offer per accepted format (config ∩ registry ∩ verifier, checked against the registry entry)
  api/tech/accept.post.ts        /tech's switches: the proof systems the site accepts
  api/tech/threads.post.ts       /tech's thread switch (Vega and BBS)
  api/tech/measurements/clear.post.ts  /tech's Clear: empties the measurements file
  utils/measurements.ts          the measurements: one JSON line per verified presentation, the /tech summary
  api/vp/session.post.ts         create session → { id, authorizationUrl }; URLs from the page's origin
  api/vp/request/[id].ts         request_uri, GET or POST (wallet_metadata, wallet_nonce), returns signed JWT
  api/vp/response/[id].post.ts   response_uri (direct_post), calls the verifier
  api/vp/session/[id]*.ts        status polling, completion (created / logged in / no account / account exists / age / ban /
                                 mismatch; community: created / logged in / linked / other_pseudonym / linked_elsewhere),
                                 cancel, phone (a swap, for /tech)
  api/test/fault.post.ts         test only (READDIT_TEST_FAULTS=1), 404 otherwise
  api/wallet/*.ts                mocked phone → prover (capabilities, sign, prove)
  api/me, logout, notice, comments, mod/*, demo/reset, tech/overview
shared/
  registry/circuits.ts           approved circuit registry (Vega and Longfellow, as the addons load them), scheme
                                 registry (BBS), PROOF_SYSTEMS (/tech's switches)
  utils/mdoc.ts                  reads an IssuerSigned (wallet screens)
  utils/negotiation.ts           tailorFormats (verifier side), selectCircuit (wallet side)
  utils/dcql.ts                  credential queries (circuit_zk, mms_zk, credential_sets), Request Object, authorization URL
  utils/pseudonym.ts             pseudonym-v1-sha256, all four configs
  types/oid4vp.ts                protocol types
native/vega/                     Rust workspace: the proof backend
  vega-age/, circuits/           nym-auth-circuits circuits and shapes, vendored unchanged (VENDOR-SHA256SUMS)
  nym-vega/                      prover steps and verifier around vega-age (OpenID4VP handover, presentation, checks)
  node/                          the napi-rs addon (Prover, Verifier)
  issuer/                        nym-issuer: the demo credentials (one per --holder), keys and trust anchor
  demo/document-signer.pem       the verifier's trust anchor
native/longfellow/               Rust workspace: the Longfellow backend (circuit_zk, the same mdoc as Vega)
  vendor/longfellow-zk/          google/longfellow-zk 61a8a73, the 11 runtime crates, unchanged (VENDOR-SHA256SUMS)
  circuits/mdoc/, fixtures/      the archive's circuits.zst, params.tsv, hash-semantic.tsv, test vectors, unchanged
  nym-longfellow/                witness (SPEC.md L3-L5), prove and verify (L6) around the runtime, OpenID4VP
                                 handover, presentation, checks (tests/flow.rs: the archive's vectors, the demo flow)
  node/                          the napi-rs addon (Prover, Verifier: the same interface as native/vega/node)
  .cargo/config.toml             carry-less multiply for GF(2^128): +pclmulqdq (x86-64), +aes (arm64, required)
native/bbs/                      Rust workspace: the BBS backend (mms_zk, docs/mms_zk.md)
  vendor/bbs-cd-plugins/         sirosfoundation/bbs-cd-plugins 0.1, vendored unchanged (VENDOR-SHA256SUMS)
  nym-bbs/                       the profile: schema, Request Object → BBS request, prover, verifier (tests/flow.rs)
  node/                          the napi-rs addon (BbsProver, BbsVerifier)
  issuer/                        bbs-issuer: the demo BBS credential (app/wallet/demo-wallet-bbs.json) and demo/issuer-params.bin
  demo/issuer-params.bin         the BBS verifier's trusted issuer key and schema
docs/mms_zk.md                   the mms_zk profile, for review
Dockerfile                       the site with the three addons (three Rust build stages); docker-compose.yml runs it
.devcontainer/devcontainer.json  GitHub Codespaces: builds the Dockerfile, runs the site on port 3000, adds CA certificates
TRY-IT.md                        how to try the demo in a codespace, for non-coders
scripts/build-native.mjs         npm run build:native
scripts/vega-check.mjs           npm run vega:check: real proofs, pseudonym, refusals
scripts/demo-flow.mjs            headless run of the presentation order: guide steps, phone traffic, screenshots
scripts/flows-check.mjs          every flow, happy and unhappy, in the browser and over HTTP (Longfellow: group L;
                                 BBS: group M; threads and measurements: group P); screenshots 19-33
```

All of the flow is real: the OpenID4VP request/response, signed Request Objects, capability
negotiation, DCQL `circuit_zk` and `mms_zk` checks on both sides, the presentation encodings, the
pseudonym derivations, the Vega, Longfellow and BBS proofs and their verification, accounts, bans and gate logic. What
is not: the holder binding (the device key and the seed sit in the page), the PIN (any PIN unlocks)
and the phone's speed (proofs run on the server's CPU).

## 4. What needs to be done

1. **Confirm the registry values** in `shared/registry/circuits.ts` with Peter: circuit ids, proof
   system ids, and the public-input order. The Vega and Longfellow entries match what the addons load
   (the site checks the id, the proof system, the public-input order and the hash of `shapes.zst` or
   `circuits.zst` at runtime). Longfellow's public inputs are its two circuits' public slots grouped
   by input; `mac.tags` and `mac.a_v` are Longfellow's own (the MAC between the two circuits).
2. **Optional: a configured request-signing certificate** (`NUXT_REQUEST_SIGNING_KEY` and
   `NUXT_REQUEST_SIGNING_CERT`). The leaf needs dNSName SAN = `siteHost`. The mocked wallet does not
   check the trust chain.
3. **Projector check.** The dialog is about 745 px tall, and the guide panel takes 352 px at the right
   edge (44 px when collapsed). Test at the venue resolution.
4. **Codespaces.** Optional prebuild (repository Settings → Codespaces) to cut the first start from
   about 10 minutes to about one. The repository must be public, or visitors added as collaborators.
5. **Longfellow: built 2026-10-19** (row Longfellow). For Peter to review: the registry entry's
   public-input names, and the handover deviation from the archive's fixtures (DC API there,
   B.2.6.1 here). `cargo test` in `native/longfellow` checks the witness against the archive's
   `test/*.bin` slot for slot and verifies its `test/proof.bin`, then proves and verifies the demo
   credentials. Not done: `scripts/vega-check.mjs` runs Vega only.

6. **BBS: built 2026-10-19** (row BBS, `docs/mms_zk.md`). For Peter to review: the profile's
   choices (§8 of `docs/mms_zk.md`: the names `mms_zk` and `pseudonym-bbs-v1`, the audience as the
   OpenID4VPHandoverInfo hash, the plugin order), and whether the presentation order should show
   both formats accepted at once (a banned mdoc account can then return with the BBS card). The
   adult's phone has no BBS credential; issuing one is `bbs-issuer --device-of 1 --birth-date
   1990-05-20` into a second file and a holder entry in `PHONES`.

## 5. Rules for changing the code

- Keep the UI and copy as they are unless asked. They have been reviewed.
- Only `server/utils/services.ts` calls the proof backends (the Vega, Longfellow and BBS addons). Keep it that way.
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
npm run build:native          # the three addons (Rust); again after changing native/vega, native/longfellow or native/bbs
npm run dev                   # http://localhost:3000
# in a container: docker compose up -d --build
# in GitHub Codespaces: see TRY-IT.md (the codespace builds the Dockerfile; after a push, Rebuild Container)
# separate windows: /tech  /mod (also linked from the guide panel's footer)
```

Checks, after every change:

```sh
npx nuxi typecheck                                  # needs: npm i --no-save typescript@5 vue-tsc
node scripts/demo-flow.mjs http://localhost:3000    # needs: npm i --no-save playwright && npx playwright install chromium
node scripts/flows-check.mjs http://localhost:3000  # every flow; start the built server as GETTING-STARTED, "Checks", says
npm run vega:check                                  # after changing native/vega
(cd native/vega && cargo test -p nym-vega)
(cd native/bbs && cargo test --release -p nym-bbs)  # after changing native/bbs: prove, verify, refusals
(cd native/bbs && sha256sum -c --quiet VENDOR-SHA256SUMS)    # the vendored bbs-cd-plugins is unchanged
(cd native/longfellow && cargo test --release -p nym-longfellow)  # after changing native/longfellow
(cd native/longfellow && sha256sum -c --quiet VENDOR-SHA256SUMS)  # the vendored longfellow-zk and the archive's files are unchanged
```

`scripts/demo-flow.mjs` runs the presentation order headlessly against the running site, including
the ban and the second sign-up, with a different PIN at each unlock. At each step it checks that the guide panel shows the
matching step, and it saves a viewport screenshot of the page: Readdit, the phone in the dialog and
the guide (`node scripts/demo-flow.mjs <base> [dir]`, default `demo-shots/`, not committed; the PR's
set was removed on 2026-10-13 because it showed the old UI).

`scripts/flows-check.mjs` drives every flow of the inventory (the PR lists them): sign-up, log-in
and log-out, the communities and age gates, the one request at a gated community when logged out,
comments, bans, both credentials and Switch credential, the wallet's refusals (decline, cancel at
the PIN, requirement not met, unsupported and untrusted requests), closing the dialog, expired and
used QR codes, an age proof from the other credential, a ban or a log-out during a request, a demo
reset, and over HTTP the verifier's refusals (replay, another state or nonce, tampered
presentations, malformed bodies, another browser) and the backend failing through the test-only
hook. It checks the product, the guide step (with the verifier's measured times after each
verified presentation) and every server answer, and that nothing carries over into the next path.
It needs the built server with `NUXT_VP_SESSION_TTL_S=40` and `READDIT_TEST_FAULTS=1`, and a
scratch `NUXT_MEASUREMENTS_FILE`, since group P clears the measurements (GETTING-STARTED, "Checks").
