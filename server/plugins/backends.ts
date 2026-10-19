// Loads the proof backends when the server starts (the Vega keys take seconds to build), so the
// first presentation does not wait. The site starts when at least one backend loads and offers
// only the formats of those that did (server/utils/vp.ts); /tech shows the one that failed and why.
// With none, the built server stops with the reasons (exit code 1). The development server keeps
// running so a fixed build can be picked up, and every wallet request answers 503 until then.
export default defineNitroPlugin(() => {
  const t0 = Date.now()
  loadBackends().then(({ vega, bbs }) => {
    const ms = Date.now() - t0
    if (!vega) console.log(`[vega] prover and verifier ready in ${ms} ms`)
    else console.warn(`[vega] not loaded: ${vega}`)
    if (!bbs) console.log(`[bbs] prover and verifier ready in ${ms} ms`)
    else console.warn(`[bbs] not loaded: ${bbs}`)
    if (vega && bbs) {
      console.error('[backends] Readdit cannot start without a proof backend. Build the addons with `npm run build:native`, then start the site again.')
      if (!import.meta.dev) process.exit(1)
    }
  })
})
