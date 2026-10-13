import tailwindcss from '@tailwindcss/vite'

export default defineNuxtConfig({
  compatibilityDate: '2026-10-01',
  devtools: { enabled: false },
  telemetry: false,
  css: ['~/assets/css/main.css'],
  vite: { plugins: [tailwindcss()] },
  runtimeConfig: {
    // Vega backend: the Rust Node addon (npm run build:native), the circuits as data and the
    // verifier's trust anchors. Paths are relative to the working directory.
    vegaAddon: 'native/vega/readdit-vega.node',
    vegaShapes: 'native/vega/circuits/mdoc/shapes.zst',
    vegaTrustAnchors: 'native/vega/demo/document-signer.pem',
    // How far proof_time may lie from the verifier's clock, in seconds.
    proofTimeToleranceS: 300,
    // Comma-separated circuit ids the site accepts, in order of preference.
    acceptedCircuits: 'urn:circuits:vega:nym_auth:v1',
    // PEM files for signing Request Objects. Empty = self-signed key and cert generated at start.
    requestSigningKey: '',
    requestSigningCert: '',
    sessionPassword: 'readdit-demo-only-session-password-0123456789abcdef',
    // How long a wallet request (its QR code) stays valid, in seconds.
    vpSessionTtlS: 600,
    public: {
      siteName: 'Readdit',
      // DNS name in the access certificate. client_id = x509_san_dns:<siteHost>
      siteHost: 'readdit.example',
    },
  },
  app: {
    head: {
      title: 'Readdit',
      htmlAttrs: { lang: 'en' },
      meta: [{ name: 'viewport', content: 'width=device-width, initial-scale=1' }],
      link: [{ rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' }],
    },
  },
})
