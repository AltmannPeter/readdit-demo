/**
 * Site: the demo's phone was swapped while this session's QR code was on screen. Recorded for the
 * technical view only; the protocol does not know about phones. Body: { phone }.
 */
export default defineEventHandler(async (event) => {
  const { s } = await getOwnedVpSession(event, getRouterParam(event, 'id')!)
  const { phone } = await readObject<{ phone: unknown }>(event)
  if (typeof phone !== 'string' || !phone || phone.length > 40) throw refusal(400, 'bad_request', 'phone is required.')
  if (s.phone !== phone) {
    s.phone = phone
    addTrace(s, 'phone', `Phone swapped: ${phone}`, { phone })
  }
  return { ok: true }
})
