/** Clear accounts, bans, comments and sessions. */
export default defineEventHandler(() => {
  resetStore()
  return { ok: true }
})
