export default defineEventHandler(async (event) => {
  const { pseudonym, reason } = await readBody<{ pseudonym?: string; reason?: string }>(event)
  const a = store().accounts.get(String(pseudonym))
  if (!a) throw createError({ statusCode: 404 })
  a.banned = { at: new Date().toISOString(), reason: reason || 'Community rules' }
  return { ok: true }
})
