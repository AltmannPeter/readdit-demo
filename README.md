# Readdit demo

Reddit-style demo site for pseudonymous sign-up, age-gated communities and bans, using the
`eu.europa.ec.eudi.nym_auth.1` attestation and `circuit_zk` presentations over cross-device OpenID4VP.

**Start here: `GETTING-STARTED.md`.** It covers starting the demo (Node or Docker) and the three
views: the site (`/`), the technical view (`/tech`) and the moderation view (`/mod`).

Quick start (Node `22.22.3+` or `24.15+`):

```sh
npm install
npm run stubs     # terminal 1: stub prover :8081, stub verifier :8082
npm run dev       # terminal 2: http://localhost:3000
```

Wallet PIN: `123456`.

- `AGENTS.md` – decisions, architecture, open work
- `docs/backend-api.md` – prover and verifier contract
