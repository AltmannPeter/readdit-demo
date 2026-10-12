export default defineEventHandler(async (event) => {
  const { pseudonym } = await readBody<{ pseudonym?: string }>(event)
  const a = store().accounts.get(String(pseudonym))
  if (!a) throw createError({ statusCode: 404 })
  delete a.banned
  return { ok: true }
})
