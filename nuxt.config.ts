import tailwindcss from '@tailwindcss/vite'

export default defineNuxtConfig({
  compatibilityDate: '2026-10-01',
  devtools: { enabled: false },
  telemetry: false,
  css: ['~/assets/css/main.css'],
  vite: { plugins: [tailwindcss()] },
  runtimeConfig: {
    // Backend services (local containers). Override with NUXT_PROVER_URL etc.
    proverUrl: 'http://localhost:8081',
    verifierUrl: 'http://localhost:8082',
    // Comma-separated circuit ids the site accepts, in order of preference.
    acceptedCircuits: 'urn:circuits:longfellow:nym_auth:v1',
    // PEM files for signing Request Objects. Empty = self-signed key and cert generated at start.
    requestSigningKey: '',
    requestSigningCert: '',
    sessionPassword: 'readdit-demo-only-session-password-0123456789abcdef',
    demoHolder: 'demo-persona',
    // 'services' = prover/verifier containers; 'offline' = built-in simulation, no services or network.
    // Switchable at runtime in /mod.
    backendMode: 'services',
    // Offline simulation: phone slowdown versus desktop (1-5), PIN and birth date.
    offlinePhoneFactor: 2,
    offlinePin: '123456',
    offlineBirthDate: '2011-03-14',
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
