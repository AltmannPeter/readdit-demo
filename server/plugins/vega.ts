// Builds the Vega prover's and verifier's keys when the server starts, so the first presentation
// does not wait for them. In offline mode the addon still loads, ready for a switch back.
export default defineNitroPlugin(() => {
  const t0 = Date.now()
  loadNative().then(
    () => console.log(`[vega] prover and verifier ready in ${Date.now() - t0} ms`),
    () => {
      /* loadNative logged the reason; /tech shows it, and the next call retries */
    },
  )
})
