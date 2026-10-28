/**
 * /tech's thread switch. Body { parallel }: true runs Vega, BBS and Longfellow's v0.5 circuits
 * (nym-auth-zk 0.3.0) on every core of this machine, false on one thread. The next prove and verify
 * calls take it (server/utils/services.ts); Longfellow's v0.4 circuits always run on one thread
 * (Google's runtime directly). A demo reset restores runtime config multithreading. Demo only: no
 * authentication, as /mod.
 */
export default defineEventHandler(async (event) => {
  const { parallel } = await readObject<{ parallel: unknown }>(event)
  if (typeof parallel !== 'boolean') throw refusal(400, 'bad_request', 'parallel must be a boolean.')
  store().multithreading = parallel
  return { ok: true, multithreading: parallel }
})
