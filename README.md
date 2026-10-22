# Community demo

Reddit-style demo site for pseudonymous sign-up, age-gated communities and bans, using the
`eu.europa.ec.eudi.nym_auth.1` attestation over cross-device OpenID4VP and the rulebook's `zkp_req`
format: circuit proofs over the mdoc (Vega or Longfellow), and BBS proofs over a BBS form of it
(`bbs_cd`, `docs/bbs_cd.md`).

**Try it in your browser, no installation:** [![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/AltmannPeter/readdit-demo?quickstart=1)
See `TRY-IT.md`.

**Run it yourself: `GETTING-STARTED.md`.** It covers starting the demo (Node or Docker) and the four
views: the site (`/`), the developer view (`/dev`), the technical view (`/tech`) and the moderation
view (`/mod`).

Quick start (Node `22.22.3+` or `24.15+`, recent stable Rust; tested with 1.98):

```sh
npm install
npm run build:native   # the Vega, Longfellow and BBS provers and verifiers, three Rust Node addons
npm run dev            # http://localhost:3000
```

Or with Docker: `docker compose up -d --build`.

Any 6-digit PIN unlocks the wallet. Three phones play the SIROS ID wallet; proofs are real Vega,
Longfellow and BBS proofs, made and verified in the site's server. The site accepts none until the
technical view switches one on. A guide panel beside the site summarises each step of the flow, with
the technical details of the step on request.

- `AGENTS.md` – decisions, architecture, open work
- `docs/backend-api.md` – prover and verifier contract
- `docs/bbs_cd.md` – the BBS encoding as the demo implements it
