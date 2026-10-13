export default defineEventHandler(async (event) => {
  const { pseudonym, reason } = await readObject<{ pseudonym: unknown; reason: unknown }>(event)
  if (typeof pseudonym !== 'string') throw refusal(400, 'bad_request', 'pseudonym is required.')
  const a = store().accounts.get(pseudonym)
  if (!a) throw refusal(404, 'unknown_account', 'Unknown account.')
  a.banned = { at: new Date().toISOString(), reason: typeof reason === 'string' && reason ? reason : 'Community rules' }
  return { ok: true }
})
