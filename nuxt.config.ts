import { existsSync, readFileSync } from 'node:fs'
import tailwindcss from '@tailwindcss/vite'

/** The commit the site is built from, read from .git without the git binary ('' outside a
 *  checkout). NUXT_PUBLIC_BUILD_COMMIT overrides it. */
function gitCommit(): string {
  try {
    const head = readFileSync('.git/HEAD', 'utf8').trim()
    if (!head.startsWith('ref:')) return /^[0-9a-f]{40}$/.test(head) ? head : ''
    const ref = head.slice(4).trim()
    if (existsSync(`.git/${ref}`)) return readFileSync(`.git/${ref}`, 'utf8').trim()
    const line = readFileSync('.git/packed-refs', 'utf8')
      .split('\n')
      .find((l) => l.endsWith(` ${ref}`))
    return line?.split(' ')[0] ?? ''
  } catch {
    return ''
  }
}

export default defineNuxtConfig({
  compatibilityDate: '2026-10-01',
  devtools: { enabled: false },
  telemetry: false,
  css: ['~/assets/css/main.css', '~/assets/css/dev.css'],
  vite: { plugins: [tailwindcss()] },
  // One-letter routes to the views (the quick links in every header, components/QuickNav.vue).
  routeRules: {
    '/c': { redirect: '/' },
    '/d': { redirect: '/dev' },
    '/t': { redirect: '/tech' },
    '/m': { redirect: '/mod' },
  },
  runtimeConfig: {
    // Vega backend: the Rust Node addon (npm run build:native), the circuits as data and the
    // verifier's trust anchors. Paths are relative to the working directory.
    vegaAddon: 'native/vega/community-vega.node',
    vegaShapes: 'native/vega/circuits/mdoc/shapes.zst',
    // Rulebook v0.5's Vega circuits (bsc). Empty: Vega proves and verifies v0.4 only.
    vegaShapesV05: 'native/vega/circuits/mdoc-bsc/shapes.zst',
    vegaTrustAnchors: 'native/vega/demo/document-signer.pem',
    // Longfellow backend: the Rust Node addon, the directory of circuits.zst, params.tsv and
    // hash-semantic.tsv, and the verifier's trust anchors (the same demo issuer as Vega's).
    longfellowAddon: 'native/longfellow/community-longfellow.node',
    longfellowCircuits: 'native/longfellow/circuits/mdoc',
    longfellowTrustAnchors: 'native/vega/demo/document-signer.pem',
    // BBS backend (bbs_cd): the Rust Node addon and the issuer parameters the verifier trusts.
    bbsAddon: 'native/bbs/community-bbs.node',
    bbsIssuerParams: 'native/bbs/demo/issuer-params.bin',
    // The demo profile at start (profiles/<id>): nym-auth-v0.4 or nym-auth-v0.5; /tech switches it.
    // Empty: the default (shared/profiles).
    demoProfile: '',
    // How far proof_time may lie from the verifier's clock, in seconds.
    proofTimeToleranceS: 300,
    // Comma-separated system ids the site can accept, circuits (mso_mdoc) and schemes (bbs_cd), in
    // order of preference.
    // The circuits the site can accept, in preference order (Vega, then Longfellow); each is offered
    // under the demo profile whose rulebook version it reads (shared/registry/circuits.ts). Ids are
    // urn:circuits:sha256:<the archive's SHA-256>: Vega v0.4, Vega v0.5, Longfellow v0.5,
    // Longfellow v0.6 (decoy digests), Longfellow v0.4.
    acceptedCircuits:
      'urn:circuits:sha256:b457ba5382eb7604ef035e790f2cb24f0cd5fdcd065f383ff1c2c49fab1bb4df,urn:circuits:sha256:7df07fefef643512270e2de4964bc1f9b6238015225cfd872e2fb35e7bb80794,urn:circuits:sha256:f4d75ee2a112c63adfb00f1da45347c4691085c8cca6ab13cee7b03f00cdbd52,urn:circuits:sha256:5d7d2b5d094032df5b02f576d2ae7b99d3f0932d47516336693f8d670cfd63ac,urn:circuits:sha256:6c4b96ed431ee547a3a2e5b62621943a9a0a44646267653bf2db0fcc269b5c3b',
    acceptedSchemes: 'urn:mms:bbs-cd:nym_auth:v1',
    // The proof systems accepted when the site starts (and after a demo reset); /tech switches
    // them. Comma-separated: vega-v1, longfellow-libzk-v1, bbs-cd-plugins-v0.1. Empty: none, so
    // the site asks for nothing until one is switched on.
    acceptedProofSystems: '',
    // Whether Vega and BBS run on every core (true) or on one thread (false) at start and after a
    // demo reset; /tech switches it. Longfellow always runs on one thread.
    multithreading: false,
    // The encrypted Response Mode requests ask for at start and after a demo reset: direct_post.cwt
    // (a CBOR response in a COSE_Encrypt, zkp_req.md §6.2) or direct_post.jwt (JSON in a JWE);
    // /tech switches it.
    responseMode: 'direct_post.cwt',
    // Where each verified presentation's measurements are appended (JSON lines); /tech shows them
    // and can clear the file. Relative to the working directory.
    measurementsFile: '.data/measurements.jsonl',
    // The profiles of /tech's Profiling switch, one JSON line per profiled presentation.
    profilesFile: '.data/profiles.jsonl',
    // /tech's "Trust new issuers": an unknown mdoc Document Signer is trusted from its first verified
    // presentation on (true at start and after a demo reset), and the issuers added that way.
    trustNewIssuers: true,
    trustedIssuersFile: '.data/trusted-issuers.json',
    // PEM files for signing Request Objects. Empty = self-signed key and cert generated at start.
    requestSigningKey: '',
    requestSigningCert: '',
    sessionPassword: 'community-demo-only-session-password-0123456789abcdef',
    // How long a wallet request (its QR code) stays valid, in seconds.
    vpSessionTtlS: 600,
    public: {
      siteName: 'Community',
      // DNS name in the access certificate. client_id = x509_san_dns:<siteHost>
      siteHost: 'community.example',
      // The repository and the commit the site is built from (/tech and /dev link to it).
      repository: 'https://github.com/AltmannPeter/readdit-demo',
      buildCommit: gitCommit(),
    },
  },
  app: {
    head: {
      title: 'Community',
      htmlAttrs: { lang: 'en' },
      meta: [{ name: 'viewport', content: 'width=device-width, initial-scale=1' }],
      link: [{ rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' }],
    },
  },
})
