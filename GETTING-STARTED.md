# Readdit demo: getting started

Readdit is a small Reddit-style site. You sign up with a pseudonym from an EU Digital Identity
Wallet, prove your age range without showing your date of birth, and stay banned if a moderator
bans you. The phone on screen plays the SIROS ID wallet. The site and the phone are mocked. The
OpenID4VP messages, the signed requests, the circuit negotiation and the zero-knowledge proofs are
real: the site's server proves and verifies with Vega, Longfellow or BBS, each compiled from Rust
into a Node addon.

**Before you start:** Readdit accepts no proof system when it starts or after a demo reset. Tick
one under **Readdit accepts** in the technical view (section 3) first; until then, sign-up, log-in
and age checks stop at "No proof accepted".

The demo has three views, each in its own browser window:

| View | Address | Who it is for |
| --- | --- | --- |
| **Site** | http://localhost:3000 | The audience: Readdit, the phone and the guide panel |
| **Technical** | http://localhost:3000/tech | Anyone who wants to see what happens underneath |
| **Moderation** | http://localhost:3000/mod | The moderator: bans and demo reset |

## 1. Start it

Pick one of the ways below. All serve all three views.

### With Node.js (recommended)

**Requires** Node.js `22.22.3` or later, or `24.15` or later (check with `node -v`;
https://nodejs.org), and a recent stable Rust for the proof addons (tested with 1.97 and 1.98; check with `cargo --version`;
https://rustup.rs).

```sh
cd readdit-demo
npm install
npm run build:native   # builds the Vega, Longfellow and BBS addons (Rust), a few minutes the first time
npm run dev            # the site
```

`npm run build:native` compiles `native/vega`, `native/longfellow` and `native/bbs` and copies the
addons to `native/vega/readdit-vega.node`, `native/longfellow/readdit-longfellow.node` and
`native/bbs/readdit-bbs.node` (`npm run build:native -- longfellow` builds one). Run it again after
changing the Rust code. When the site starts, it loads the three and logs `[vega] prover and
verifier ready`, `[longfellow] …` and `[bbs] …`. It starts with the ones that load.

### With Docker (no Node.js needed)

**Requires** Docker with Compose. Check with `docker compose version`.

```sh
cd readdit-demo
docker compose up -d --build      # first run takes several minutes: it compiles the Rust addons
docker compose down               # to stop
```

The image builds each addon in its own Rust stage and runs the site with them. There are no separate
prover or verifier containers. On a shared machine, `docker compose build --build-arg JOBS=4`
limits the Rust build's parallel jobs.

### In GitHub Codespaces (nothing to install)

Open the repository on GitHub and click **Open in GitHub Codespaces** in the README. The codespace
builds the same image as Docker and opens Readdit in a browser tab. Instead of `localhost:3000`,
the three views are at the codespace's address (`https://<name>-3000.app.github.dev`, plus `/tech`
and `/mod`). Step by step, for people who do not code: `TRY-IT.md`.

Then open the three addresses above in three separate browser windows. A good layout: the site
full screen on the projector, and the technical and moderation views on the laptop screen.

**Proof backends.** Proofs come from a **prover** and a **verifier**, in addons that the site's
server loads. The prover plays the phone's native steps: the PIN unlocks the device key, which signs
the request; then the witness and the proof. The verifier checks the proof against Readdit's own
request. Vega (`native/vega`) and Longfellow (`native/longfellow`) prove the same nym_auth statement
over the same mdoc credential, each with its own circuits from the nym-auth-circuits archive; BBS
(`native/bbs`) proves it over a BBS credential.

## 2. The site view

**http://localhost:3000** is Readdit as the audience sees it, with the guide panel on the right.
Log in, sign up and age checks open a dialog with a QR code on the left and a phone on the right.

**Three phones, one credential each.** **Teen's phone** (born 14 March 2011) and **Adult's phone**
(born 20 May 1990) each hold an "Age and pseudonym" credential (an mdoc). **Teen's BBS phone** holds
the teen's "Age and pseudonym (BBS)", the same credential as a BBS credential (teal card); it can
answer only when Readdit accepts BBS (technical view, "Readdit accepts"). The dialog shows one
phone, named above it with its owner's age, in its own frame colour (grey, red or teal). **Swap
phone** hands over to the next one (teen, adult, teen's BBS, then the teen's again) while the QR
code is on screen, for example to show someone borrowing another person's phone. The chosen phone
stays until you swap again; reloading the page starts on the teen's phone.

Logged out, the home page and the open communities show no posts, only a short note on how
Readdit accounts work, with **Sign up** and **Log in**.

Sign up and log in send the same wallet request, a pseudonym; Readdit applies it differently.
**Sign up** only creates an account: when the wallet already has one, the dialog says "Account
already exists" and offers **Log in**. **Log in** only logs in: with no account for the wallet, the dialog says "No
account" and offers **Sign up**.

On the phone (SIROS ID), the screens and their wording follow the SIROS ID wallet:

- **The round QR button** at the bottom reads the code on screen.
- **Request to Share Data** shows the requester's domain and one card per item requested:
  **Age proof** with the range or threshold (`Age proof: 13–17`), when the site asks, and
  **Pseudonym**, specific to the site, with what that means: personal data is not shared, no
  tracking across sites, the site can recognize the account, the issuer may be able to reveal
  the identity.
  **Share** accepts; **Decline** declines, and nothing is shared.
- **Enter the Pin:** any 6 digits, then **Submit**. You can tap the digits or type them. Any PIN
  unlocks the wallet in this demo, and none leaves the phone.
- While proving and sending, the phone shows "Creating presentation...", then "Sending
  response...", then "Success!". The dialog stays open until you press **Close** on the phone.
- **Cancel** at the PIN declines as **Decline** does: "Sharing Cancelled", and nothing is shared.
- A QR code works once and for 10 minutes. Scanning it again, or after it expired, shows
  "Request Expired"; the dialog's **Try again** shows a new one.
- **The "Age and pseudonym" card** shows the holder's birth date, and opens the credential: birth
  date, issuance date, and **Presentations**, the list of presentations made with it. The
  credentials do not expire, so no expiry date is shown.

**The guide panel** follows the flow by itself. For the current step it shows a title and a short
summary; **Details** opens the technical facts of that step: the request, the pseudonym's properties
under `known-offender-matching-ssc`, what is and is not shared, the proof's measured time and size,
the verification's measured time (decoding, verification, and the verifier call as Readdit timed
it, all on this machine), and what Readdit checks. All of it is derived from the actual request, credential and metrics.
The panel's button at the top right collapses it to a narrow strip; the browser remembers the
choice. Its footer links to the technical and moderation views.

Each credential has its own secret seed, so each phone gives Readdit a different pseudonym and so a
different account. The guide names the phone in use at every step.

Communities:

- **Open communities** (c/photography, c/cooking and others) need only a login.
- **c/teenspace** is for ages 13–17. The teen's phone gets in; the adult's phone meets
  "Requirement Not Met".
- **c/afterdark** is for ages 18+. On the teen's phone the wallet shows "Requirement Not Met", and
  nothing is shared. Swap to the adult's phone at the QR code: it makes the proof, but Readdit rejects
  it when you are logged in with the teen's account ("Pseudonym does not match"). Logged out, or
  logged in with the adult's account, you get in.
- **c/france** (badge "Proof of human") is about French politics and society and wants real people,
  no bots. It has its own pseudonym: **Join with wallet** asks for a pseudonym for
  `france.readdit.example`, so each person gets one c/france account, not linked to their Readdit
  account unless they choose to (only the issuer could link it otherwise). No age limit and no Readdit account needed. Posts and comments
  there are visible only with a c/france account, and appear under the c/france pseudonym. Logged in
  to Readdit, you choose: **Join and link to u/…**, or **Log out and join separately**. A Readdit
  account can be linked to one c/france account only, and the other way round. A ban in c/france
  does not touch the Readdit account; a ban of the Readdit account also bans the linked c/france
  account, and unbanning lifts both.
  With only a c/france account, the header shows it with a "c/france" mark.
- **Logged out**, an age-restricted community shows its age requirement and **Verify age with
  wallet**. That one request asks for the pseudonym and the age range together: it creates the
  account or logs in to it, and records the age. If the requirement is not met, nothing is shared
  and the visitor stays logged out.

Closing the dialog before the request ends cancels it: an answer the phone sends later is refused,
and nothing changes.

Logged-in users can vote, join communities and comment.

## 3. The technical view

**http://localhost:3000/tech** updates live while you use the site. It shows the newest wallet
session; the chips under the service cards select earlier ones, and name the phone that was on
screen.

- **Badge (top right).** The addons that are loaded: "Vega, Longfellow and BBS addons, in process".
- **Readdit accepts.** Switches for the proof systems Readdit accepts: Vega and Longfellow (circuits
  over the mdoc, `mso_mdoc`) and BBS (`bbs_cd`). None is ticked at start or after **Reset demo**:
  tick one before the demo. Vega and Longfellow use the same credential and give the same
  pseudonym, so the same account; with both ticked the request lists both circuits, Vega first, and
  the wallet uses Vega. With BBS and an mdoc system on, the request (`zkp_req`) offers both source
  formats, and the phone on screen answers with its credential: the teen's phone with the mdoc,
  the teen's BBS phone with the BBS credential. The two give different pseudonyms, so different
  accounts. Only the ticked ones count, also for a QR code already on screen.
- **Multithreading (Vega and BBS).** Off at start and after **Reset demo**: Vega and BBS run on
  one thread. On, they run on one thread per core, and the line next to the switch says how many.
  Longfellow always runs on one thread: Google's runtime has no parallel code.
- **Prover and verifier cards** (Vega, Longfellow and BBS). Whether they are loaded, their
  implementation and version, the time they took to load once at start, the threads they run on
  now, and the circuit they run. The verifier card
  shows its trust anchor and the `proof_time` tolerance. **Request signing** shows the certificate
  that signs Readdit's requests.
- **Tiles.** Session status, prove time (witness and proof), verify time, proof size and
  presentation size, and the size of the signed request.
- **Flow.** Each step with its time from the start of the session: session created, request
  fetched (with or without wallet metadata), device key signed, witness built (its
  size and `proof_time`), proof created (witness and prove times, the server process's peak
  memory), presentation received, proof verified or rejected (with the rule and the public input
  that failed), result applied to the account, or why not (cancelled, expired, no account,
  banned, a different account).
- **Request.** What Readdit asked for (pseudonym, age range). **Raw JSON** shows the full signed
  Request Object.
- **Capability negotiation.** Per format, the circuits or schemes Readdit accepts, the ones the
  wallet supports, the ones sent in the request, and the one used.
- **Circuit** (mdoc). The circuit's public inputs in order, and for each one whether it comes from
  the presentation or Readdit computes it itself. **Scheme** (BBS): what Readdit derives from the
  request, and what each plugin proves.
- **Public outputs.** What Readdit learned: the pseudonym and, for age checks, `true`.
- **Measured on this server.** Every presentation proved through the phone and verified, saved to
  `.data/measurements.jsonl` (it survives restarts and **Reset demo**): per proof system, what was
  proven (pseudonym, or pseudonym and age) and thread count, the number of runs, prove and verify
  times (median and range), proof and presentation size, and the server process's peak memory.
  Prove is the phone's work, run here on the server's CPU, so a phone would be slower. The line
  above the table names this machine. **Clear** (click twice) empties the file. Desktop times are measurements on Apple M5 and AMD Ryzen 9 (BBS: a 2-core cloud VM). Phone times are
  not measured yet: they are desktop times multiplied by 1–5. Sending the proof assumes a 5–50 Mbit/s
  mobile uplink. The bottom row gives the time per presentation.

## 4. The moderation view

**http://localhost:3000/mod** is the moderator's page. Nothing on the site links to it.

- **Recent comments.** Each comment has a **Ban user** button.
- **Accounts.** Every account with its pseudonym (all Readdit knows about it), join date, age checks
  passed and status, with **Ban** or **Unban**. A c/france account linked to a Readdit account is
  listed under it; an unlinked one stands on its own.
- **Reset demo** (top right). Click it twice to clear all accounts, bans, comments and sessions.
  An open wallet dialog then says "This code is no longer valid. Try again."

A ban logs the user out within a few seconds and hides their comments. The site view shows a ban
notice. Signing up again with the same wallet ends in "Account banned", because the wallet always
gives Readdit the same pseudonym.

## 5. A full run through all three views

0. **Technical:** tick Vega under "Readdit accepts" (nothing is ticked at start).
1. **Site:** sign up on the teen's phone (scan, **Share**, any 6-digit PIN, **Close** on the phone).
   You get a pseudonym such as `u/golden-lynx-8604`.
   **Technical:** the session, the negotiation and the pseudonym appear.
2. **Site:** open c/afterdark. The phone says the requirement is not met. **Technical:** the
   session ends with an error response, and no proof is created.
3. **Site:** **Try again**, then **Swap phone** to the adult's phone, and share. Readdit says
   "Pseudonym does not match": the proof is valid, but it is not the teen's account's.
   **Technical:** the session shows the swap and a verified proof that was not applied.
4. **Site:** open c/teenspace and verify on the teen's phone. You get in. **Technical:** the request
   now holds a pseudonym and an age range, and the outputs are the same pseudonym and `true`.
5. **Site:** open c/afterdark again. Readdit refuses on its own, without asking the wallet.
6. **Site:** open c/france and **Join and link to u/…** on the teen's phone. The request's client_id is
   `x509_san_dns:france.readdit.example`; you get a second pseudonym, linked to your account.
7. **Site:** comment on a c/teenspace post. **Moderation:** click **Ban user** on that comment.
   **Site:** the ban notice appears.
8. **Site:** sign up again with the same wallet. Readdit shows "Account banned". **Moderation:**
   it is still the same single account.
9. **BBS.** **Moderation:** **Reset demo**. **Technical:** tick BBS under "Readdit accepts" (the
   reset unticked Vega; tick it too to offer both formats). **Site:** **Swap phone** to the teen's
   BBS phone and sign up. Then c/teenspace: the age range is proven with BBS. **Technical:** the proof's parts (BBS proof, device binding, pseudonym, age
   range) and sizes.
10. **Longfellow.** **Moderation:** **Reset demo**. **Technical:** tick Longfellow. **Site:** sign up
   on the teen's phone, try c/afterdark (requirement not met), then c/teenspace. **Technical:** the
   circuit used is `urn:circuits:longfellow:nym_auth:v1`; the proof is about 344 kB. Without the
   reset, logging in with Longfellow reaches the account made with Vega: the pseudonym is the same.

**Start over:** in the moderation view, click **Reset demo** twice, then reload the site window.

## 6. When the proof backend fails

Readdit has three proof backends, the Vega, Longfellow and BBS addons. There is no fallback.

- **An addon is missing or cannot load.** The site starts with the others and logs, for example,
  `[longfellow] not loaded: …`; the technical view's cards say why, and its switch for that proof
  system is off. With none, the built site (`npm run start`, Docker) stops at start with
  `[backends] Readdit cannot start without a proof backend. Build the addons with npm run
  build:native, then start the site again.` The development server keeps running, so that a
  rebuilt addon is picked up on restart; until then every wallet dialog says "Verification is not
  available right now. Try again later."
- **One proof or one verification fails.** The phone shows "Signing Failed" (the proof was not
  made) or "Response Error" (Readdit could not verify it), and the dialog "Not completed:
  Verification is not available right now". Nothing is applied. **Try again** starts a new request.
  The server log has a `[vega] … failed`, `[longfellow] …`, `[bbs] …` or `[circuits] …` line
  with the reason, and the technical view the session.

**Before the event:** build the addons on the presentation laptop (`npm run build:native`), start the
site, tick the proof system you will show in the technical view, and run the whole demo once.

## Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `NUXT_VEGA_ADDON` | `native/vega/readdit-vega.node` | The Vega addon (`npm run build:native`) |
| `NUXT_VEGA_SHAPES` | `native/vega/circuits/mdoc/shapes.zst` | The circuits as data |
| `NUXT_VEGA_TRUST_ANCHORS` | `native/vega/demo/document-signer.pem` | Issuer certificates the verifier trusts |
| `NUXT_PROOF_TIME_TOLERANCE_S` | `300` | How far a proof's time may lie from the server's clock, in seconds |
| `NUXT_LONGFELLOW_ADDON` | `native/longfellow/readdit-longfellow.node` | The Longfellow addon |
| `NUXT_LONGFELLOW_CIRCUITS` | `native/longfellow/circuits/mdoc` | Its circuits: `circuits.zst`, `params.tsv`, `hash-semantic.tsv` |
| `NUXT_LONGFELLOW_TRUST_ANCHORS` | `native/vega/demo/document-signer.pem` | Issuer certificates the Longfellow verifier trusts (the same demo issuer) |
| `NUXT_ACCEPTED_CIRCUITS` | `urn:circuits:vega:nym_auth:v1,urn:circuits:longfellow:nym_auth:v1` | Circuits the site can accept, in preference order |
| `NUXT_BBS_ADDON` | `native/bbs/readdit-bbs.node` | The BBS addon |
| `NUXT_BBS_ISSUER_PARAMS` | `native/bbs/demo/issuer-params.bin` | The BBS issuer the verifier trusts |
| `NUXT_ACCEPTED_PROOF_SYSTEMS` | empty | Proof systems accepted at start and after a reset (`vega-v1`, `longfellow-libzk-v1`, `bbs-cd-plugins-v0.1`, comma-separated); empty: none, the technical view switches them on |
| `NUXT_MULTITHREADING` | `false` | Vega and BBS on every core at start and after a reset; the technical view switches it |
| `NUXT_MEASUREMENTS_FILE` | `.data/measurements.jsonl` | Where the technical view's measurements are kept (JSON lines) |
| `NUXT_PUBLIC_SITE_HOST` | `readdit.example` | DNS name in `client_id` and the request-signing certificate |
| `NUXT_VP_SESSION_TTL_S` | `600` | How long a wallet request (its QR code) stays valid, in seconds |

The demo person's birth date is in the credential itself (`app/wallet/demo-wallet.json`); see
"The demo credential" below to issue another. With Docker, set variables in `docker-compose.yml`.

## Troubleshooting

- **The site stops at start with `Readdit cannot start without a proof backend`.** Run
  `npm run build:native`, then start the site again.
- **"Connection Error" on the phone** (development server). No addon is loaded. The technical
  view's prover cards say why. Run `npm run build:native` and restart the site.
- **"No proof accepted" in the dialog.** Nothing is ticked under "Readdit accepts" (the start
  state, and after **Reset demo**): tick a proof system in the technical view.
- **"Verification is not available".** The addon of every ticked proof system failed to load: tick
  one whose cards are green in the technical view.
- **Port already in use** (3000). Stop whatever uses it. On macOS or Linux, `lsof -i :3000` finds it.
- **`npm install` warns about vulnerabilities.** They are in Nuxt's build and dev tools, not in the
  demo code. Do not run `npm audit fix --force`: it downgrades Nuxt and breaks the site.
- **`npm install` warns about install scripts** (esbuild, fsevents, cbor-extract). The demo works
  without them. If `npm run dev` fails on esbuild, run `npm install-scripts approve esbuild`, then
  `npm install` again.

## The demo credential

The phone carries two real `eu.europa.ec.eudi.nym_auth.1` mdocs (born 14 March 2011 and 20 May
1990), each with its own device key and secret seed, in `app/wallet/demo-wallet.json`. The demo has
no true holder binding: a real wallet keeps the device key in secure hardware. Vega and Longfellow
prove over the same mdocs. Their verifiers trust the demo issuer's Document Signer certificate, `native/vega/demo/document-signer.pem`, which signed
both. They come from `nym-issuer`, which issues under the nym-auth-circuits profile, prints each
credential's three lengths (Sig_structure 423 B, birth_date item 95 B, ssc item 108 B) and checks
them before writing:

```sh
cd native/vega
cargo run --release -p nym-issuer -- --holder 2011-03-14 --holder 1990-05-20 \
  --valid-from 2026-10-13 --valid-until 9999-12-31T23:59:59Z --keep ../../app/wallet/demo-wallet.json \
  --wallet-out ../../app/wallet/demo-wallet.json --trust-out demo/document-signer.pem
```

The credentials do not expire: `validUntil` is `9999-12-31T23:59:59Z`, the farthest an mdoc tdate
holds, and the Document Signer certificate's `notAfter` is `99991231235959Z`, RFC 5280's value for
no well-defined expiration. `--keep` reuses each holder's device key and secret seed from the
current wallet file, so the pseudonyms and the accounts stay the same; without it, each run makes
new keys and seeds, and the pseudonyms change. `--days N` (or `--holder DATE:N`) gives a validity of
N days instead. The issuer's key is written nowhere. Restart the site after a re-issue.

The teen's BBS credential (`app/wallet/demo-wallet-bbs.json`) comes from `bbs-issuer`, with the
teen's mdoc device key, and a `secret_seed` attribute derived from the teen's 16-byte seed
(hash_to_scalar, `docs/bbs_cd.md`); the BBS verifier trusts `native/bbs/demo/issuer-params.bin`. A
re-issue makes a new issuer key; the BBS pseudonyms stay the same as long as the teen's mdoc seed
does:

```sh
cd native/bbs
cargo run --release -p bbs-issuer -- --wallet ../../app/wallet/demo-wallet.json --device-of 0 \
  --birth-date 2011-03-14 --out ../../app/wallet/demo-wallet-bbs.json --issuer-params demo/issuer-params.bin
```

## Checks

```sh
npm run vega:check                              # real proofs of both credentials: pseudonyms, refusals, any PIN, 18+ (needs build:native)
(cd native/vega && cargo test -p nym-vega)      # the OpenID4VP handover against the spec's example, age_check mapping
(cd native/vega && sha256sum -c VENDOR-SHA256SUMS)  # vendored circuits unchanged
(cd native/bbs && cargo test --release -p nym-bbs)  # BBS: prove, verify, the same pseudonym, refusals
(cd native/bbs && sha256sum -c --quiet VENDOR-SHA256SUMS)  # vendored bbs-cd-plugins unchanged
(cd native/longfellow && cargo test --release -p nym-longfellow)  # Longfellow: the archive's test vectors, then prove and verify the demo mdocs
(cd native/longfellow && sha256sum -c --quiet VENDOR-SHA256SUMS)  # vendored longfellow-zk and the archive's circuits unchanged
npx nuxi typecheck                              # first: npm i --no-save typescript@5 vue-tsc
node scripts/demo-flow.mjs http://localhost:3000    # the presentation order, with screenshots
node scripts/flows-check.mjs http://localhost:3000  # every flow, happy and unhappy (server settings below)
```

`scripts/flows-check.mjs` drives every flow: in the browser where a person can reach it, and over
HTTP for replays, tampered presentations, malformed bodies and expiry. It needs the built site
started with two settings, which it checks first:

```sh
npm run build
NUXT_MEASUREMENTS_FILE=/tmp/readdit-measurements.jsonl NUXT_VP_SESSION_TTL_S=40 READDIT_TEST_FAULTS=1 PORT=3000 \
  node .output/server/index.mjs > /tmp/server.log 2>&1 &
node scripts/flows-check.mjs http://localhost:3000 --server-log /tmp/server.log --startup .output/server/index.mjs
```

Requests then expire after 40 s, so the expiry paths take a minute. `READDIT_TEST_FAULTS=1` turns
on a test-only route that makes the next call of one addon step fail, for the "backend failing"
paths; never set it for the demo. `--shots <dir>` saves the run's screenshots (19 to 33);
`--only M` runs one self-contained group (L is Longfellow, M is BBS, P the thread switch and the
measurements). The scratch measurements file keeps the run's proofs out of the demo's own
measurements, which group P clears.

## More

- `docs/nym_auth_rulebook.md` – the Nym-authentication Attestation Specification and Rulebook: the
  attestation, how pseudonyms and age checks are requested and proven, and how presentations are
  verified.
- `AGENTS.md` – design decisions, architecture, open work. Written for developers and coding agents.
- `docs/backend-api.md` – the prover and verifier interface (the Vega, Longfellow and BBS addons).
- `docs/bbs_cd.md` – how the demo implements the rulebook's BBS encoding (`bbs_cd`): credential,
  request, binding, presentation, verification.
- `scripts/demo-flow.mjs` – runs the walkthrough headlessly, checks that the guide panel follows
  each step, and saves a viewport screenshot of each step. Needs Playwright:
  `npm i --no-save playwright && npx playwright install chromium`, then
  `node scripts/demo-flow.mjs http://localhost:3000` (screenshots in `demo-shots/`).
- `scripts/flows-check.mjs` – drives every flow, happy and unhappy, and checks the product, the
  guide and the servers' answers (see "Checks").
