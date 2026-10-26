/**
 * /tech's Profiling switch. Body { on }: true samples every addon step from the next call on
 * (server/utils/services.ts, server/utils/profiles.ts); the profiles stay when it is switched off.
 * Off at start and after a demo reset. Demo only: no authentication, as /mod.
 */
export default defineEventHandler(async (event) => {
  const { on } = await readObject<{ on: unknown }>(event)
  if (typeof on !== 'boolean') throw refusal(400, 'bad_request', 'on must be a boolean.')
  store().profiling = on
  return { ok: true, profiling: on }
})
