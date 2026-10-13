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

On the phone (SIROS ID), the screens and their wording follow the SIROS ID wallet:

- **The round QR button** at the bottom reads the code on screen.
- **Request to Share Data** shows the requester (name and domain) and the requested information
  in the credential's box: a pseudonym specific to the site, and the age range when the site asks
  for one. **Share** accepts; **Decline** declines, and nothing is shared.
- **Enter the Pin:** `123456`, then **Submit**. You can tap the digits or type them. A wrong PIN is
  rejected and the wallet asks again.
- While proving and sending, the phone shows "Creating presentation...", then "Sending
  response...", then "Success!".
- **The "Age and pseudonym" card** opens the credential: birth date, issuance and expiry dates,
  and **Presentations**, the list of presentations made with it.

**The guide panel** follows the flow by itself. For the current step it shows a title and a short
summary; **Details** opens the technical facts of that step: the request, the pseudonym's properties
under `known-offender-matching-ssc`, what is and is not shared, the proof's measured time and size,
and what Readdit checks. All of it is derived from the actual request, credential and metrics.
The panel's button at the top right collapses it to a narrow strip; the browser remembers the
choice. Its footer links to the technical and moderation views.

The demo person is 15 years old (born 14 March 2011).

Communities:

- **Open communities** (c/photography, c/cooking and others) need only a login.
- **c/teenspace** is for ages 13–17. The demo person gets in.
- **c/afterdark** is for ages 18+. The wallet shows "Requirement Not Met", and nothing is shared.

Logged-in users can vote, join communities and comment.

## 3. The technical view

**http://localhost:3000/tech** updates live while you use the site. It shows the newest wallet
session; the chips under the service cards select earlier ones.

- **Badge (top right).** "Vega addon, in process" or "Offline simulation".
- **Prover and verifier cards.** Whether they are loaded, their implementation and version, the
  time they took to build their keys once at start, and the circuit they run. The verifier card
  shows its trust anchor and the `proof_time` tolerance. **OFFLINE** means the built-in
  simulation. **Request signing** shows the certificate that signs Readdit's requests.
- **Tiles.** Session status, prove time (witness and proof), verify time, proof size and
  presentation size, and the size of the signed request. Values from the offline simulation are
  marked **simulated**.
- **Flow.** Each step with its time from the start of the session: session created, request
  fetched (with or without wallet metadata), PIN checked and device key signed, witness built (its
  size and `proof_time`), proof created (witness and prove times, the server process's peak
  memory), presentation received, proof verified or rejected (with the rule and the public input
  that failed), and result applied to the account.
- **Request.** What Readdit asked for (pseudonym, age range). **Raw JSON** shows the full signed
  Request Object.
- **Capability negotiation.** The circuits Readdit accepts, the circuits the wallet supports, the
  ones sent in the request, and the one used.
- **Circuit.** The circuit's public inputs in order, and for each one whether it comes from the
  presentation or Readdit computes it itself.
- **Public outputs.** What Readdit learned: the pseudonym and, for age checks, `true`.
- **Estimates per step.** Setup, precompute, prove, send and verify, for Longfellow
  and VegaMC (in use). Desktop times are measurements on Apple M5 and AMD Ryzen 9. Phone times are
  not measured yet: they are desktop times multiplied by 1–5. Sending the proof assumes a 5–50 Mbit/s
  mobile uplink. The bottom row gives the time per presentation.

## 4. The moderation view

**http://localhost:3000/mod** is the moderator's page. Nothing on the site links to it.

- **Recent comments.** Each comment has a **Ban user** button.
- **Accounts.** Every account with its pseudonym (all Readdit knows about it), join date, age checks
  passed and status, with **Ban** or **Unban**.
- **Proof backend** (top). **Vega** uses the Vega addon. **Offline** uses the built-in simulation
  (see section 6). With Offline, **Simulated phone speed** sets how much slower
  than a desktop the simulated phone is (×1 to ×5).
- **Reset demo** (top right). Click it twice to clear all accounts, bans, comments and sessions.
  It does not change the proof backend.

A ban logs the user out within a few seconds and hides their comments. The site view shows a ban
notice. Signing up again with the same wallet ends in "Account banned", because the wallet always
gives Readdit the same pseudonym.

## 5. A full run through all three views

1. **Site:** sign up (scan, **Share**, PIN `123456`). You get a pseudonym such as `u/golden-lynx-8604`.
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

## 6. Offline backup

If the addon fails (or cannot be built on the presentation laptop), switch to the built-in
offline simulation. It needs no addon and no network.

**During the demo:** in the moderation view, set **Proof backend** to **Offline**. If a wallet
dialog shows "Verification is not available right now", click **Try again**. The site looks and
behaves the same. The technical view shows **Offline simulation** and marks its numbers as
simulated.

**Start in offline mode from the beginning:**

```sh
npm run dev:offline                    # development server
npm run build && npm run start:offline # built site, without the development server
```

With Docker, add `NUXT_BACKEND_MODE: offline` under `web: environment:` in `docker-compose.yml`,
or switch in the moderation view.

**What the simulation does.** It checks the PIN, reads the birth date from the credential the
wallet sends and checks the age range, derives the real pseudonym from the wallet's seed, and sends
a presentation with a random proof of Vega's size (96.1 kB). It waits as long as Vega would on a
phone, from the nym-auth-circuits benchmark (1 thread): 0.77 s × the simulated phone speed for the
witness and the proof, 0.06 s to verify. It does not create or verify a zero-knowledge proof.

**Before the event:**

1. Run `npm install` (and `npm run build` if you use `start:offline`) while you are online.
2. Turn off Wi-Fi and run the whole demo once in offline mode.
3. Keep the moderation view open in a window you can reach quickly.

## Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `NUXT_VEGA_ADDON` | `native/vega/readdit-vega.node` | The Vega addon (`npm run build:native`) |
| `NUXT_VEGA_SHAPES` | `native/vega/circuits/mdoc/shapes.zst` | The circuits as data |
| `NUXT_VEGA_TRUST_ANCHORS` | `native/vega/demo/document-signer.pem` | Issuer certificates the verifier trusts |
| `NUXT_PROOF_TIME_TOLERANCE_S` | `300` | How far a proof's time may lie from the server's clock, in seconds |
| `NUXT_WALLET_PIN` | `123456` | The wallet PIN, with the addon and in offline mode |
| `NUXT_ACCEPTED_CIRCUITS` | `urn:circuits:vega:nym_auth:v1` | Circuits the site accepts, in preference order |
| `NUXT_PUBLIC_SITE_HOST` | `readdit.example` | DNS name in `client_id` and the request-signing certificate |
| `NUXT_BACKEND_MODE` | `native` | `offline` starts with the built-in simulation |
| `NUXT_OFFLINE_PHONE_FACTOR` | `2` | Simulated phone speed, desktop ×1–5 |

The demo person's birth date is in the credential itself (`app/wallet/demo-wallet.json`); see
"The demo credential" below to issue another. With Docker, set variables in `docker-compose.yml`.

## Troubleshooting

- **"Connection Error" on the phone.** The Vega addon is not loaded. The technical view's prover
  card says why. Run `npm run build:native` and restart the site, or switch to **Offline** in the
  moderation view.
- **Port already in use** (3000). Stop whatever uses it. On macOS or Linux, `lsof -i :3000` finds it.
- **`npm install` warns about vulnerabilities.** They are in Nuxt's build and dev tools, not in the
  demo code. Do not run `npm audit fix --force`: it downgrades Nuxt and breaks the site.
- **`npm install` warns about install scripts** (esbuild, fsevents, cbor-extract). The demo works
  without them. If `npm run dev` fails on esbuild, run `npm install-scripts approve esbuild`, then
  `npm install` again.

## The demo credential

The phone carries a real `eu.europa.ec.eudi.nym_auth.1` mdoc (born 14 March 2011), its device key
and its secret seed, in `app/wallet/demo-wallet.json`. The demo has no true holder binding: a real
wallet keeps the device key in secure hardware. The verifier trusts the demo issuer's Document
Signer certificate, `native/vega/demo/document-signer.pem`. Both come from `nym-issuer`, which
issues under the nym-auth-circuits profile and checks its lengths before writing:

```sh
cd native/vega
cargo run --release -p nym-issuer -- --birth-date 2011-03-14 \
  --wallet-out ../../app/wallet/demo-wallet.json --trust-out demo/document-signer.pem
```

The credential is valid from the day before issuing for 366 days (`--valid-from`, `--days`). Each
run makes new keys and a new seed, so the pseudonym and the accounts change; restart the site after it.

## Checks

```sh
npm run vega:check                              # real proofs: pseudonym, refusals, PIN, 18+ (needs build:native)
(cd native/vega && cargo test -p nym-vega)      # the OpenID4VP handover against the spec's example, age_check mapping
(cd native/vega && sha256sum -c VENDOR-SHA256SUMS)  # vendored circuits unchanged
npx nuxi typecheck                              # first: npm i --no-save typescript@5 vue-tsc
node scripts/demo-flow.mjs http://localhost:3000    # the presentation order, with screenshots
```

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
