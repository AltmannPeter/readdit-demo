// Loads the proof backends when the server starts (the Vega keys take seconds to build), so the
// first presentation does not wait. The site starts when at least one backend loads and offers
// only the circuits and formats of those that did (server/utils/vp.ts); /tech shows the ones that
// failed and why. With none, the built server stops with the reasons (exit code 1). The development
// server keeps running so a fixed build can be picked up, and every wallet request answers 503
// until then.
export default defineNitroPlugin(() => {
  const t0 = Date.now()
  loadBackends().then((errors) => {
    const ms = Date.now() - t0
    for (const [name, error] of Object.entries(errors)) {
      if (!error) console.log(`[${name}] prover and verifier ready in ${ms} ms`)
      else console.warn(`[${name}] not loaded: ${error}`)
    }
    if (Object.values(errors).every(Boolean)) {
      console.error('[backends] Readdit cannot start without a proof backend. Build the addons with `npm run build:native`, then start the site again.')
      if (!import.meta.dev) process.exit(1)
    }
  })
})
