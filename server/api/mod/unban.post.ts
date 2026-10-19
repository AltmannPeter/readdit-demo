/** Unban an account. Unbanning a Readdit account also lifts the bans its own ban put on linked accounts. */
export default defineEventHandler(async (event) => {
  const { pseudonym } = await readObject<{ pseudonym: unknown }>(event)
  if (typeof pseudonym !== 'string') throw refusal(400, 'bad_request', 'pseudonym is required.')
  const a = store().accounts.get(pseudonym)
  if (!a) throw refusal(404, 'unknown_account', 'Unknown account.')
  delete a.banned
  if (!a.community) {
    for (const linked of store().accounts.values()) if (linked.linkedTo === a.pseudonym && linked.banned?.cascade) delete linked.banned
  }
  return { ok: true }
})
