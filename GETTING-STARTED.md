# Readdit demo: getting started

Readdit is a small Reddit-style site. You sign up with a pseudonym from an EU Digital Identity
Wallet, prove your age range without showing your date of birth, and stay banned if a moderator
bans you. The phone on screen plays the wallet. The site and the phone are mocked. The OpenID4VP
messages, the signed requests, the circuit negotiation and the proof calls are real.

The demo has three views, each in its own browser window:

| View | Address | Who it is for |
| --- | --- | --- |
| **Site** | http://localhost:3000 | The audience: Readdit and the phone |
| **Technical** | http://localhost:3000/tech | Anyone who wants to see what happens underneath |
| **Moderation** | http://localhost:3000/mod | The moderator: bans and demo reset |

## 1. Start it

Pick one of the two ways below. Both serve all three views.

### With Node.js (recommended)

**Requires** Node.js `22.22.3` or later, or `24.15` or later. Check with `node -v`. Download from
https://nodejs.org if needed.

```sh
cd readdit-demo
npm install
npm run stubs        # terminal 1: backend services, leave running
npm run dev          # terminal 2: the site
```

### With Docker (no Node.js needed)

**Requires** Docker with Compose. Check with `docker compose version`.

```sh
cd readdit-demo
docker compose --profile full up -d --build      # first run takes a few minutes
docker compose --profile full down               # to stop
```

Then open the three addresses above in three separate browser windows. A good layout: the site
full screen on the projector, and the technical and moderation views on the laptop screen.

**Backend services.** Proofs come from a **prover** and a **verifier** service. This package
includes stub versions of both. They follow the real interface but do not create or check a
zero-knowledge proof, and the technical view marks them **STUB**. To run the real Longfellow
services, see the appendix.

## 2. The site view

**http://localhost:3000** is Readdit as the audience sees it. Log in, sign up and age checks open a
dialog with a QR code on the left and the person's phone on the right.

On the phone (EUDI Wallet App):

- **Scan QR code** reads the code on screen.
- **Continue** accepts the request. **Cancel** declines it, and nothing is shared.
- **PIN:** `123456`. You can tap it or type it on the keyboard. A wrong PIN is rejected.
- **The "Age and pseudonym" card** opens the credential details in a new window: date of birth,
  seed commitment, issuer, validity, device key, and what a site receives. Allow pop-ups for
  localhost if the browser blocks it.

The demo person is 15 years old (born 14 March 2011).

Communities:

- **Open communities** (c/photography, c/cooking and others) need only a login.
- **c/teenspace** is for ages 13–17. The demo person gets in.
- **c/afterdark** is for ages 18+. The wallet says the requirement is not met, and nothing is shared.

Logged-in users can vote, join communities and comment.

## 3. The technical view

**http://localhost:3000/tech** updates live while you use the site. It shows the newest wallet
session; the chips under the service cards select earlier ones.

- **Badge (top right).** "Backend services" or "Offline simulation".
- **Service cards.** Whether the prover and verifier are reachable, their implementation and
  version, and the circuits they support. **STUB** means no real proof. **OFFLINE** means the
  built-in simulation. **Request signing** shows the certificate that signs Readdit's requests.
- **Tiles.** Session status, prove time, verify time, proof size and presentation size, and the
  size of the signed request. Values from the offline simulation are marked **simulated**.
- **Flow.** Each step with its time from the start of the session: session created, request
  fetched (with or without wallet metadata), proof created, presentation received, proof verified
  or rejected, and result applied to the account.
- **Request.** What Readdit asked for (pseudonym, age range). **Raw JSON** shows the full signed
  Request Object.
- **Capability negotiation.** The circuits Readdit accepts, the circuits the wallet supports, the
  ones sent in the request, and the one used.
- **Circuit.** The circuit's public inputs in order, and for each one whether it comes from the
  presentation or Readdit computes it itself.
- **Public outputs.** What Readdit learned: the pseudonym and, for age checks, `true`.
- **What it takes: estimates per step.** Setup, precompute, prove, send and verify, for Longfellow
  (in use) and VegaMC. Desktop times are measurements on Apple M5 and AMD Ryzen 9. Phone times are
  not measured yet: they are desktop times multiplied by 1–5. Sending the proof assumes a 5–50 Mbit/s
  mobile uplink. The bottom row gives the time per presentation.

## 4. The moderation view

**http://localhost:3000/mod** is the moderator's page. Nothing on the site links to it.

- **Recent comments.** Each comment has a **Ban user** button.
- **Accounts.** Every account with its pseudonym (all Readdit knows about it), join date, age checks
  passed and status, with **Ban** or **Unban**.
- **Proof backend** (top). **Services** uses the prover and verifier services. **Offline** uses the
  built-in simulation (see section 6). With Offline, **Simulated phone speed** sets how much slower
  than a desktop the simulated phone is (×1 to ×5).
- **Reset demo** (top right). Click it twice to clear all accounts, bans, comments and sessions.
  It does not change the proof backend.

A ban logs the user out within a few seconds and hides their comments. The site view shows a ban
notice. Signing up again with the same wallet ends in "Account banned", because the wallet always
gives Readdit the same pseudonym.

## 5. A full run through all three views

1. **Site:** log in (Scan, Continue, PIN `123456`). You get a pseudonym such as `u/golden-lynx-8604`.
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

If the services or the network fail during a presentation, switch to the built-in offline
simulation. It needs no prover or verifier service and no network.

**During the demo:** in the moderation view, set **Proof backend** to **Offline**. If a wallet
dialog shows "The verification service is not available", click **Try again**. The site looks and
behaves the same. The technical view shows **Offline simulation** and marks its numbers as
simulated.

**Start in offline mode from the beginning:**

```sh
npm run dev:offline                    # development server
npm run build && npm run start:offline # built site; more robust for a presentation
```

With Docker, add `NUXT_BACKEND_MODE: offline` under `web: environment:` in `docker-compose.yml`,
or switch in the moderation view.

**What the simulation does.** It checks the PIN and the age range, derives the real pseudonym, and
sends a presentation with a random proof of Longfellow's size (345.6 kB). It waits as long as
Longfellow would on a phone: 0.36 s × the simulated phone speed to prove, 0.17 s to verify. It does
not create or verify a zero-knowledge proof.

**Before the event:**

1. Run `npm install` (and `npm run build` if you use `start:offline`) while you are online.
2. Turn off Wi-Fi and run the whole demo once in offline mode.
3. Keep the moderation view open in a window you can reach quickly.

## Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `NUXT_PROVER_URL` | `http://localhost:8081` | Prover service |
| `NUXT_VERIFIER_URL` | `http://localhost:8082` | Verifier service |
| `NUXT_ACCEPTED_CIRCUITS` | `urn:circuits:longfellow:nym_auth:v1` | Circuits the site accepts, in preference order |
| `NUXT_PUBLIC_SITE_HOST` | `readdit.example` | DNS name in `client_id` and the request-signing certificate |
| `NUXT_BACKEND_MODE` | `services` | `offline` starts with the built-in simulation |
| `NUXT_OFFLINE_PHONE_FACTOR` | `2` | Simulated phone speed, desktop ×1–5 |
| `NUXT_OFFLINE_PIN` | `123456` | PIN in offline mode |
| `NUXT_OFFLINE_BIRTH_DATE` | `2011-03-14` | Birth date in offline mode |

The stub prover reads `DEMO_PIN` (default `123456`) and `DEMO_BIRTH_DATE` (default `2011-03-14`).
With Docker, change them in `docker-compose.yml`.

## Troubleshooting

- **"The wallet service is not available" on the phone.** The backend is not running. Start
  `npm run stubs`, check `docker compose --profile full ps`, or switch to **Offline** in the
  moderation view.
- **Port already in use** (3000, 8081 or 8082). Stop whatever uses it. On macOS or Linux,
  `lsof -i :3000` finds it.
- **The credential window does not open.** Allow pop-ups for localhost.
- **`npm install` warns about vulnerabilities.** They are in Nuxt's build and dev tools, not in the
  demo code. Do not run `npm audit fix --force`: it downgrades Nuxt and breaks the site.
- **`npm install` warns about install scripts** (esbuild, fsevents, cbor-extract). The demo works
  without them. If `npm run dev` fails on esbuild, run `npm install-scripts approve esbuild`, then
  `npm install` again.

## Appendix: the Longfellow backend

This needs Docker and the Longfellow prover and verifier images, which are not in this package.
Both must implement `docs/backend-api.md` and listen on port 8080 inside the container.

```sh
export LONGFELLOW_PROVER_IMAGE=<prover image>
export LONGFELLOW_VERIFIER_IMAGE=<verifier image>
docker compose -f docker-compose.yml -f docker-compose.longfellow.yml --profile full up -d --build
```

On Windows PowerShell, set the variables with `$env:LONGFELLOW_PROVER_IMAGE="<prover image>"` and
`$env:LONGFELLOW_VERIFIER_IMAGE="<verifier image>"`. On an Apple-chip Mac, images built only for
Intel need Rosetta: turn it on in Docker Desktop, or run `colima start --vm-type vz --vz-rosetta`.

The technical view then shows the Longfellow services with no STUB badge, and the prove, verify and
proof tiles show real times and sizes.

## More

- `docs/nym_auth_rulebook.md` – the Nym-authentication Attestation Specification and Rulebook: the
  attestation, how pseudonyms and age checks are requested and proven, and how presentations are
  verified.
- `AGENTS.md` – design decisions, architecture, open work. Written for developers and coding agents.
- `docs/backend-api.md` – the prover and verifier HTTP interface.
- `scripts/demo-flow.mjs` – runs the walkthrough headlessly and saves screenshots. Needs Playwright:
  `npm i -D playwright && npx playwright install chromium`, then
  `node scripts/demo-flow.mjs http://localhost:3000`.
