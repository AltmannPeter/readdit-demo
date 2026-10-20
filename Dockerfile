# Readdit site (Nuxt) with its three proof backends compiled in as Node addons (Rust): Vega and
# Longfellow (circuits over mso_mdoc, native/vega and native/longfellow) and BBS (bbs_cd, native/bbs).
#   docker compose up -d --build        then http://localhost:3000

# 1. The Vega addon: native/vega/node, built against the vendored vega-age and its locked dependencies.
FROM rust:1-bookworm AS native
# Optional: --build-arg JOBS=4 limits Cargo's parallel jobs on a shared machine.
ARG JOBS
WORKDIR /native
COPY native/vega ./
RUN if [ -n "$JOBS" ]; then export CARGO_BUILD_JOBS="$JOBS"; fi \
 && cargo build --release --locked -p readdit-vega-node \
 && cp target/release/libreaddit_vega_node.so readdit-vega.node

# 2. The BBS addon: native/bbs/node, built against the vendored bbs-cd-plugins and its locked dependencies.
FROM rust:1-bookworm AS native-bbs
ARG JOBS
WORKDIR /native
COPY native/bbs ./
RUN if [ -n "$JOBS" ]; then export CARGO_BUILD_JOBS="$JOBS"; fi \
 && cargo build --release --locked -p readdit-bbs-node \
 && cp target/release/libreaddit_bbs_node.so readdit-bbs.node

# 3. The Longfellow addon: native/longfellow/node, built against the vendored longfellow-zk crates
#    and its locked dependencies. native/longfellow/.cargo/config.toml enables carry-less multiply
#    (PCLMULQDQ on x86-64, PMULL on arm64), which Google's GF(2^128) code needs.
FROM rust:1-bookworm AS native-longfellow
ARG JOBS
WORKDIR /native
COPY native/longfellow ./
RUN if [ -n "$JOBS" ]; then export CARGO_BUILD_JOBS="$JOBS"; fi \
 && cargo build --release --locked -p readdit-longfellow-node \
 && cp target/release/libreaddit_longfellow_node.so readdit-longfellow.node

# 4. The site.
FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY . .
RUN npm install --no-audit --no-fund && npm run build

# 5. Runtime: the built site, the addons, the circuits as data and the verifiers' trust anchors, at
#    the paths runtimeConfig expects relative to /app (nuxt.config.ts: vegaAddon, vegaShapes,
#    vegaTrustAnchors, longfellowAddon, longfellowCircuits, longfellowTrustAnchors, bbsAddon,
#    bbsIssuerParams).
FROM node:24-bookworm-slim
WORKDIR /app
COPY --from=build /app/.output ./.output
COPY --from=native /native/readdit-vega.node ./native/vega/readdit-vega.node
COPY --from=native-longfellow /native/readdit-longfellow.node ./native/longfellow/readdit-longfellow.node
COPY --from=native-bbs /native/readdit-bbs.node ./native/bbs/readdit-bbs.node
COPY native/vega/circuits/mdoc/shapes.zst ./native/vega/circuits/mdoc/shapes.zst
COPY native/vega/demo/document-signer.pem ./native/vega/demo/document-signer.pem
COPY native/longfellow/circuits/mdoc/circuits.zst native/longfellow/circuits/mdoc/params.tsv native/longfellow/circuits/mdoc/hash-semantic.tsv ./native/longfellow/circuits/mdoc/
COPY native/bbs/demo/issuer-params.bin ./native/bbs/demo/issuer-params.bin
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3000
EXPOSE 3000
CMD ["node", ".output/server/index.mjs"]
