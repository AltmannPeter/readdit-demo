import { ENCRYPTED_RESPONSE_MODES, type EncryptedResponseMode } from '#shared/types/oid4vp'

/**
 * /tech's Response switch. Body { mode }: `direct_post.cwt` (a CBOR response in a COSE_Encrypt,
 * zkp_req.md §6.2) or `direct_post.jwt` (JSON in a JWE). Requests made from now on ask for it,
 * also for a QR code already on screen (the request is made when the wallet fetches it); a request
 * already fetched keeps the mode it asked for. A demo reset restores runtime config responseMode.
 * Demo only: no authentication, as /mod.
 */
export default defineEventHandler(async (event) => {
  const { mode } = await readObject<{ mode: unknown }>(event)
  if (!ENCRYPTED_RESPONSE_MODES.includes(mode as EncryptedResponseMode)) {
    throw refusal(400, 'bad_request', `mode must be one of ${ENCRYPTED_RESPONSE_MODES.join(', ')}.`)
  }
  store().responseMode = mode as EncryptedResponseMode
  return { ok: true, responseMode: store().responseMode }
})
