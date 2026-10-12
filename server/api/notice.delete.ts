/** Dismiss the ban notice. */
export default defineEventHandler(async (event) => {
  const b = await browserSession(event)
  store().bannedNotices.delete(b.data.sid!)
  return { ok: true }
})
