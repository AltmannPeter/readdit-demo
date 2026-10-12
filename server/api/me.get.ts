/** Current account of this browser. A ban ends the login and leaves a notice once. */
export default defineEventHandler(async (event) => {
  const b = await browserSession(event)
  const { accounts, bannedNotices } = store()
  const account = b.data.pseudonym ? accounts.get(b.data.pseudonym) : undefined
  if (account?.banned) {
    await b.update({ pseudonym: undefined })
    bannedNotices.set(b.data.sid!, account.handle)
  }
  if (account && !account.banned) return { account: publicAccount(account), bannedHandle: null }
  if (b.data.pseudonym && !account) await b.update({ pseudonym: undefined })
  const bannedHandle = bannedNotices.get(b.data.sid!) ?? null
  return { account: null, bannedHandle }
})
