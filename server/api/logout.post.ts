export default defineEventHandler(async (event) => {
  const b = await browserSession(event)
  store().bannedNotices.delete(b.data.sid!)
  await b.update({ pseudonym: undefined })
  return { ok: true }
})
