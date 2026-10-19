import { PROOF_SYSTEMS } from '#shared/registry/circuits'

/**
 * The operator's switch in /tech: whether the site accepts a proof system. Body { proof_system,
 * accept }. The next wallet request offers the formats of the accepted ones (server/utils/vp.ts).
 * Refused: 400 bad_request (unknown proof system), 409 last_proof_system (the site must accept at
 * least one). A demo reset restores the configured ones. Demo only: no authentication, as /mod.
 */
export default defineEventHandler(async (event) => {
  const { proof_system: id, accept } = await readObject<{ proof_system: unknown; accept: unknown }>(event)
  if (typeof id !== 'string' || !PROOF_SYSTEMS.some((p) => p.id === id) || typeof accept !== 'boolean') {
    throw refusal(400, 'bad_request', `proof_system must be one of ${PROOF_SYSTEMS.map((p) => p.id).join(', ')}, accept a boolean.`)
  }
  const st = store()
  const now = st.acceptedProofSystems.filter((p) => p !== id)
  if (accept) now.push(id)
  if (!now.length) throw refusal(409, 'last_proof_system', 'The site must accept at least one proof system.')
  // Keep the registry's order, which is the order of preference.
  st.acceptedProofSystems = PROOF_SYSTEMS.map((p) => p.id).filter((p) => now.includes(p))
  return { ok: true, acceptedProofSystems: st.acceptedProofSystems }
})
