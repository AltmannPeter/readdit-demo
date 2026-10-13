# Readdit demo: getting started

Readdit is a small Reddit-style site. You sign up with a pseudonym from an EU Digital Identity
Wallet, prove your age range without showing your date of birth, and stay banned if a moderator
bans you. The phone on screen plays the SIROS ID wallet. The site and the phone are mocked. The
OpenID4VP messages, the signed requests, the circuit negotiation and the zero-knowledge proofs are
real: the site's server proves and verifies with Vega, compiled from Rust into a Node addon.

The demo has three views, each in its own browser window:

| View | Address | Who it is for |
| --- | --- | --- |
| **Site** | http://localhost:3000 | The audience: Readdit, the phone and the guide panel |
| **Technical** | http://localhost:3000/tech | Anyone who wants to see what happens underneath |
| **Moderation** | http://localhost:3000/mod | The moderator: bans and demo reset |

## 1. Start it

Pick one of the two ways below. Both serve all three views.

### With Node.js (recommended)

**Requires** Node.js `22.22.3` or later, or `24.15` or later (check with `node -v`;
https://nodejs.org), and a recent stable Rust for the proof addon (tested with 1.98; check with `cargo --version`;
https://rustup.rs).

```sh
cd readdit-demo
npm install
npm run build:native   # builds the Vega addon (Rust), a few minutes the first time
npm run dev            # the site
```

`npm run build:native` compiles `native/vega` and copies the addon to
`native/vega/readdit-vega.node`. Run it again after changing the Rust code. When the site starts,
it builds the prover's and the verifier's keys once (about half a second) and logs
`[vega] prover and verifier ready`.

### With Docker (no Node.js needed)

**Requires** Docker with Compose. Check with `docker compose version`.

```sh
cd readdit-demo
docker compose up -d --build      # first run takes several minutes: it compiles the Rust addon
docker compose down               # to stop
```

The image builds the addon in a Rust stage and runs the site with it. There are no separate
prover or verifier containers. On a shared machine, `docker compose build --build-arg JOBS=4`
limits the Rust build's parallel jobs.

Then open the three addresses above in three separate browser windows. A good layout: the site
full screen on the projector, and the technical and moderation views on the laptop screen.

**Proof backend.** Proofs come from a **prover** and a **verifier**, both in the Vega addon that
the site's server loads. The prover plays the phone's native steps: the PIN unlocks the device key,
which signs the request; then the witness and the proof. The verifier checks the proof against
Readdit's own request. The circuits are the nym_auth Vega circuits from the nym-auth-circuits
archive (`native/vega`).

## 2. The site view

**http://localhost:3000** is Readdit as the audience sees it, with the guide panel on the right.
Log in, sign up and age checks open a dialog with a QR code on the left and the person's phone on
the right.

Sign up and log in send the same wallet request, a pseudonym; Readdit applies it differently.
**Sign up** only creates an account: when the wallet already has one, the dialog says "Account
already exists" and offers **Log in**. **Log in** only logs in: with no account for the wallet, the dialog says "No
account" and offers **Sign up**.

On the phone (SIROS ID), the screens and their wording follow the SIROS ID wallet:

- **The round QR button** at the bottom reads the code on screen.
- **Request to Share Data** shows the requester (name and domain) and the requested information
  in the credential's box: a pseudonym specific to the site, and the age range when the site asks
  for one. **Share** accepts; **Decline** declines, and nothing is shared. **Switch credential**
  chooses the wallet's other credential (see below).
- **Enter the Pin:** any 6 digits, then **Submit**. You can tap the digits or type them. Any PIN
  unlocks the wallet in this demo, and none leaves the phone.
- While proving and sending, the phone shows "Creating presentation...", then "Sending
  response...", then "Success!".
- **Cancel** at the PIN declines as **Decline** does: "Sharing Cancelled", and nothing is shared.
- A QR code works once and for 10 minutes. Scanning it again, or after it expired, shows
  "Request Expired"; the dialog's **Try again** shows a new one.
- **The "Age and pseudonym" cards** show each holder's birth date, and open the credential: birth
  date, issuance date, and **Presentations**, the list of presentations made with it. The
  credentials do not expire, so no expiry date is shown.

**The guide panel** follows the flow by itself. For the current step it shows a title and a short
summary; **Details** opens the technical facts of that step: the request, the pseudonym's properties
under `known-offender-matching-ssc`, what is and is not shared, the proof's measured time and size,
the verification's measured time (decoding, verification, and the verifier call as Readdit timed
it, all on this machine), and what Readdit checks. All of it is derived from the actual request, credential and metrics.
The panel's button at the top right collapses it to a narrow strip; the browser remembers the
choice. Its footer links to the technical and moderation views.

The wallet holds two "Age and pseudonym" credentials, told apart by the birth date on each card:
the demo person's, 15 years old (born 14 March 2011), and an adult's (born 20 May 1990). A request
uses the credential shown on the wallet's home screen. Each has its own secret seed, so
each gives Readdit a different pseudonym and so a different account. When both match a request,
**Switch credential** on the request screen, or on "Requirement Not Met", chooses the other one.

Communities:

- **Open communities** (c/photography, c/cooking and others) need only a login.
- **c/teenspace** is for ages 13–17. The demo person gets in; the adult credential meets
  "Requirement Not Met".
- **c/afterdark** is for ages 18+. With the demo person's credential the wallet shows "Requirement
  Not Met", and nothing is shared. With the adult credential (**Switch credential**, or shown on the
  home screen before scanning) the wallet makes the proof, but Readdit rejects it when you are logged
  in with the demo person's account ("Pseudonym does not match"). Logged out, or logged in with the
  adult's account, you get in.
- **Logged out**, an age-restricted community shows its age requirement and **Verify age with
  wallet**. That one request asks for the pseudonym and the age range together: it creates the
  account or logs in to it, and records the age. If the requirement is not met, nothing is shared
  and the visitor stays logged out.

Closing the dialog before the request ends cancels it: an answer the phone sends later is refused,
and nothing changes.

Logged-in users can vote, join communities and comment.

## 3. The technical view

**http://localhost:3000/tech** updates live while you use the site. It shows the newest wallet
session; the chips under the service cards select earlier ones.

- **Badge (top right).** "Vega addon, in process", or "Vega addon not loaded" (only the
  development server keeps running without the addon; see section 6).
- **Prover and verifier cards.** Whether they are loaded, their implementation and version, the
  time they took to build their keys once at start, and the circuit they run. The verifier card
  shows its trust anchor and the `proof_time` tolerance. **Request signing** shows the certificate
  that signs Readdit's requests.
- **Tiles.** Session status, prove time (witness and proof), verify time, proof size and
  presentation size, and the size of the signed request.
- **Flow.** Each step with its time from the start of the session: session created, request
  fetched (with or without wallet metadata), PIN checked and device key signed, witness built (its
  size and `proof_time`), proof created (witness and prove times, the server process's peak
  memory), presentation received, proof verified or rejected (with the rule and the public input
  that failed), result applied to the account, or why not (cancelled, expired, no account,
  banned, a different account).
- **Request.** What Readdit asked for (pseudonym, age range). **Raw JSON** shows the full signed
  Request Object.
- **Capability negotiation.** The circuits Readdit accepts, the circuits the wallet supports, the
  ones sent in the request, and the one used.
- **Circuit.** The circuit's public inputs in order, and for each one whether it comes from the
  presentation or Readdit computes it itself.
- **Public outputs.** What Readdit learned: the pseudonym and, for age checks, `true`.
- **Estimates per step.** Setup, precompute, prove, send and verify, for Longfellow
  and VegaMC. Desktop times are measurements on Apple M5 and AMD Ryzen 9. Phone times are
  not measured yet: they are desktop times multiplied by 1–5. Sending the proof assumes a 5–50 Mbit/s
  mobile uplink. The bottom row gives the time per presentation.

## 4. The moderation view

**http://localhost:3000/mod** is the moderator's page. Nothing on the site links to it.

- **Recent comments.** Each comment has a **Ban user** button.
- **Accounts.** Every account with its pseudonym (all Readdit knows about it), join date, age checks
  passed and status, with **Ban** or **Unban**.
- **Reset demo** (top right). Click it twice to clear all accounts, bans, comments and sessions.
  An open wallet dialog then says "This code is no longer valid. Try again."

A ban logs the user out within a few seconds and hides their comments. The site view shows a ban
notice. Signing up again with the same wallet ends in "Account banned", because the wallet always
gives Readdit the same pseudonym.

## 5. A full run through all three views

1. **Site:** sign up (scan, **Share**, any 6-digit PIN). You get a pseudonym such as `u/golden-lynx-8604`.
   **Technical:** the session, the negotiation and the pseudonym appear.
2. **Site:** open c/afterdark. The phone says the requirement is not met. **Technical:** the
   session ends with an error response, and no proof is created.
3. **Site:** open c/teenspace and verify. You get in. **Technical:** the request now holds a
   pseudonym and an age range, and the outputs are the same pseudonym and `true`.
4. **Site:** open c/afterdark again. Readdit refuses on its own, without asking the wallet.
5. **Site:** comment on a c/teenspace post. **Moderation:** click **Ban user** on that comment.
   **Site:** the ban notice appears.
6. **Site:** sign up again with the same wallet. Readdit shows "Account banned". **Moderation:**
   it is still the same single account.

**Start over:** in the moderation view, click **Reset demo** twice, then reload the site window.

## 6. When the proof backend fails

The Vega addon is Readdit's only proof backend. There is no fallback.

- **The addon is missing or cannot load.** The built site (`npm run start`, Docker) stops at start
  with `[vega] Readdit cannot start without its proof backend: …` and `Build the Vega addon with
  npm run build:native, then start the site again.` The development server keeps running, so that
  a rebuilt addon is picked up on restart; until then every wallet dialog says "Verification is not
  available right now. Try again later."
- **One proof or one verification fails.** The phone shows "Signing Failed" (the proof was not
  made) or "Response Error" (Readdit could not verify it), and the dialog "Not completed:
  Verification is not available right now". Nothing is applied. **Try again** starts a new request.
  The server log has a `[vega] … failed` line with the reason, and the technical view the session.

**Before the event:** build the addon on the presentation laptop (`npm run build:native`), start the
site and run the whole demo once.

## Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `NUXT_VEGA_ADDON` | `native/vega/readdit-vega.node` | The Vega addon (`npm run build:native`) |
| `NUXT_VEGA_SHAPES` | `native/vega/circuits/mdoc/shapes.zst` | The circuits as data |
| `NUXT_VEGA_TRUST_ANCHORS` | `native/vega/demo/document-signer.pem` | Issuer certificates the verifier trusts |
| `NUXT_PROOF_TIME_TOLERANCE_S` | `300` | How far a proof's time may lie from the server's clock, in seconds |
| `NUXT_ACCEPTED_CIRCUITS` | `urn:circuits:vega:nym_auth:v1` | Circuits the site accepts, in preference order |
| `NUXT_PUBLIC_SITE_HOST` | `readdit.example` | DNS name in `client_id` and the request-signing certificate |
| `NUXT_VP_SESSION_TTL_S` | `600` | How long a wallet request (its QR code) stays valid, in seconds |

The demo person's birth date is in the credential itself (`app/wallet/demo-wallet.json`); see
"The demo credential" below to issue another. With Docker, set variables in `docker-compose.yml`.

## Troubleshooting

- **The site stops at start with `[vega] Readdit cannot start without its proof backend`.** Run
  `npm run build:native`, then start the site again.
- **"Connection Error" on the phone** (development server). The Vega addon is not loaded. The
  technical view's prover card says why. Run `npm run build:native` and restart the site.
- **Port already in use** (3000). Stop whatever uses it. On macOS or Linux, `lsof -i :3000` finds it.
- **`npm install` warns about vulnerabilities.** They are in Nuxt's build and dev tools, not in the
  demo code. Do not run `npm audit fix --force`: it downgrades Nuxt and breaks the site.
- **`npm install` warns about install scripts** (esbuild, fsevents, cbor-extract). The demo works
  without them. If `npm run dev` fails on esbuild, run `npm install-scripts approve esbuild`, then
  `npm install` again.

## The demo credential

The phone carries two real `eu.europa.ec.eudi.nym_auth.1` mdocs (born 14 March 2011 and 20 May
1990), each with its own device key and secret seed, in `app/wallet/demo-wallet.json`. The demo has
no true holder binding: a real wallet keeps the device key in secure hardware. The verifier trusts
the demo issuer's Document Signer certificate, `native/vega/demo/document-signer.pem`, which signed
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

## Checks

```sh
npm run vega:check                              # real proofs of both credentials: pseudonyms, refusals, any PIN, 18+ (needs build:native)
(cd native/vega && cargo test -p nym-vega)      # the OpenID4VP handover against the spec's example, age_check mapping
(cd native/vega && sha256sum -c VENDOR-SHA256SUMS)  # vendored circuits unchanged
npx nuxi typecheck                              # first: npm i --no-save typescript@5 vue-tsc
node scripts/demo-flow.mjs http://localhost:3000    # the presentation order, with screenshots
node scripts/flows-check.mjs http://localhost:3000  # every flow, happy and unhappy (server settings below)
```

`scripts/flows-check.mjs` drives every flow: in the browser where a person can reach it, and over
HTTP for replays, tampered presentations, malformed bodies and expiry. It needs the built site
started with two settings, which it checks first:

```sh
npm run build
NUXT_VP_SESSION_TTL_S=40 READDIT_TEST_FAULTS=1 PORT=3000 node .output/server/index.mjs > /tmp/server.log 2>&1 &
node scripts/flows-check.mjs http://localhost:3000 --server-log /tmp/server.log --startup .output/server/index.mjs
```

Requests then expire after 40 s, so the expiry paths take a minute. `READDIT_TEST_FAULTS=1` turns
on a test-only route that makes the next call of one addon step fail, for the "backend failing"
paths; never set it for the demo. `--shots <dir>` saves the run's screenshots (19 to 29).

## Appendix: the Longfellow backend

Readdit now proves and verifies with Vega in process. `docker-compose.longfellow.yml` is kept
unchanged from the earlier design, in which the site called Longfellow prover and verifier images
over HTTP. The site no longer makes those calls, so the override has no effect on it; a Longfellow
backend would plug into `server/utils/services.ts` as the Vega addon does.

## More

- `docs/nym_auth_rulebook.md` – the Nym-authentication Attestation Specification and Rulebook: the
  attestation, how pseudonyms and age checks are requested and proven, and how presentations are
  verified.
- `AGENTS.md` – design decisions, architecture, open work. Written for developers and coding agents.
- `docs/backend-api.md` – the prover and verifier interface (the Vega addon).
- `scripts/demo-flow.mjs` – runs the walkthrough headlessly, checks that the guide panel follows
  each step, and saves a viewport screenshot of each step. Needs Playwright:
  `npm i --no-save playwright && npx playwright install chromium`, then
  `node scripts/demo-flow.mjs http://localhost:3000`. The PR's screenshots are in
  `docs/screenshots/vega-siros-wallet/`.
- `scripts/flows-check.mjs` – drives every flow, happy and unhappy, and checks the product, the
  guide and the servers' answers (see "Checks").
