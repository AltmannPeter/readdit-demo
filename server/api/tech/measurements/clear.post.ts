/** /tech's Clear: empties the measurements file (server/utils/measurements.ts). Demo only: no authentication, as /mod. */
export default defineEventHandler(async () => {
  await clearMeasurements()
  return { ok: true }
})
