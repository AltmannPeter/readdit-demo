# Readdit demo

Reddit-style demo site for pseudonymous sign-up, age-gated communities and bans, using the
`eu.europa.ec.eudi.nym_auth.1` attestation and `circuit_zk` presentations over cross-device OpenID4VP.

**Start here: `GETTING-STARTED.md`.** It covers starting the demo (Node or Docker) and the three
views: the site (`/`), the technical view (`/tech`) and the moderation view (`/mod`).

Quick start (Node `22.22.3+` or `24.15+`, recent stable Rust; tested with 1.98):

```sh
npm install
npm run build:native   # the Vega prover and verifier, a Rust Node addon
npm run dev            # http://localhost:3000
```

Or with Docker: `docker compose up -d --build`.

Wallet PIN: `123456`. The phone plays the SIROS ID wallet; proofs are real Vega proofs, made and
verified in the site's server. A guide panel beside the site summarises each step of the flow, with
the technical details of the step on request.

- `AGENTS.md` – decisions, architecture, open work
- `docs/backend-api.md` – prover and verifier contract
