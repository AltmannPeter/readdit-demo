/**
 * /tech's Profiling switch. Body { on }: true samples every addon step from the next call on
 * (server/utils/services.ts, server/utils/profiles.ts); the profiles stay when it is switched off.
 * 'full' does the same and also keeps every sample's whole stack, for exports (`npm run bench
 * profiling=full`). Off at start and after a demo reset. Demo only: no authentication, as /mod.
 */
export default defineEventHandler(async (event) => {
  const { on } = await readObject<{ on: unknown }>(event)
  if (typeof on !== 'boolean' && on !== 'full') throw refusal(400, 'bad_request', 'on must be a boolean or "full".')
  store().profiling = on
  return { ok: true, profiling: on }
})
