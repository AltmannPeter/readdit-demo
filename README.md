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

**Benchmarks from the terminal.** With the site running (`npm run build && npm run start`, or
`npm run dev`), `npm run bench` makes presentations through the demo phone's routes and prints
`/tech`'s Benchmark figures for those runs. `npm run bench help` lists the options;
`GETTING-STARTED.md` ("Benchmarks from the terminal") has more examples. Under v0.7:

```sh
npm run bench runs=30 profile=v0.7 system=longfellow threads=1,4 age=13-17
```

Under v0.7 only Longfellow can be benchmarked; Vega and BBS are pending. The demo's Longfellow
backend, for every rulebook version, runs google/longfellow-zk `61a8a73` without upstream's fix
`7ec62ec` (carries in the P-256 field's multiply-accumulation, 24 October 2026). The v0.7 prover and
verifier both use that function, so the figures here are optimistic: with the fix, verify takes about
1.5 times as long and prove about 5% longer. The circuits repository's `nym-auth-v07-longfellow`
benchmarks the same circuits with the fix.

- `AGENTS.md` – decisions, architecture, open work
- `docs/backend-api.md` – prover and verifier contract
- `docs/bbs_cd.md` – the BBS encoding as the demo implements it
