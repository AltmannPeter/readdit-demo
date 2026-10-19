/**
 * Ban an account. Banning a Readdit account also bans the community accounts linked to it
 * (`cascade`: lifted again when the Readdit account is unbanned). Banning a community account
 * leaves the Readdit account and its other community accounts alone.
 */
export default defineEventHandler(async (event) => {
  const { pseudonym, reason } = await readObject<{ pseudonym: unknown; reason: unknown }>(event)
  if (typeof pseudonym !== 'string') throw refusal(400, 'bad_request', 'pseudonym is required.')
  const a = store().accounts.get(pseudonym)
  if (!a) throw refusal(404, 'unknown_account', 'Unknown account.')
  const at = new Date().toISOString()
  a.banned = { at, reason: typeof reason === 'string' && reason ? reason : 'Community rules' }
  if (!a.community) {
    for (const linked of store().accounts.values()) {
      if (linked.linkedTo === a.pseudonym && !linked.banned) linked.banned = { at, reason: `Readdit account u/${a.handle} banned`, cascade: true }
    }
  }
  return { ok: true }
})
