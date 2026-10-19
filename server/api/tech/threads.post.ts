/**
 * /tech's thread switch. Body { parallel }: true runs Vega and BBS on every core of this machine,
 * false on one thread. The next prove and verify calls take it (server/utils/services.ts);
 * Longfellow always runs on one thread (Google's runtime has no parallel code). A demo reset
 * restores runtime config multithreading. Demo only: no authentication, as /mod.
 */
export default defineEventHandler(async (event) => {
  const { parallel } = await readObject<{ parallel: unknown }>(event)
  if (typeof parallel !== 'boolean') throw refusal(400, 'bad_request', 'parallel must be a boolean.')
  store().multithreading = parallel
  return { ok: true, multithreading: parallel }
})
