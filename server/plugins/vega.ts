// Builds the Vega prover's and verifier's keys when the server starts, so the first presentation
// does not wait for them. The addon is Readdit's only proof backend: when it cannot load, the
// built server stops with the reason (exit code 1). The development server keeps running so a
// fixed build can be picked up, and every wallet request answers 503 until then.
export default defineNitroPlugin(() => {
  const t0 = Date.now()
  loadNative().then(
    () => console.log(`[vega] prover and verifier ready in ${Date.now() - t0} ms`),
    (e: Error) => {
      console.error(`[vega] Readdit cannot start without its proof backend: ${e.message}`)
      console.error('[vega] Build the Vega addon with `npm run build:native`, then start the site again.')
      if (!import.meta.dev) process.exit(1)
    },
  )
})
