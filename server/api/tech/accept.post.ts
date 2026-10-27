import { PROOF_SYSTEMS } from '#shared/registry/circuits'
import { systemStatus } from '#shared/profiles'

/**
 * The operator's switch in /tech: whether the site accepts a proof system. Body { proof_system,
 * accept }. The next wallet request offers the formats of the accepted ones (server/utils/vp.ts).
 * With none accepted, the site starts no wallet request (503 none_accepted). Refused: 400
 * bad_request (unknown proof system), 409 pending_system (the demo profile cannot use it yet, e.g.
 * nym_auth v0.5 waiting for its circuits; /tech shows why). A demo reset restores the configured ones (none, by default).
 * Demo only: no authentication, as /mod.
 */
export default defineEventHandler(async (event) => {
  const { proof_system: id, accept } = await readObject<{ proof_system: unknown; accept: unknown }>(event)
  if (typeof id !== 'string' || !PROOF_SYSTEMS.some((p) => p.id === id) || typeof accept !== 'boolean') {
    throw refusal(400, 'bad_request', `proof_system must be one of ${PROOF_SYSTEMS.map((p) => p.id).join(', ')}, accept a boolean.`)
  }
  const status = systemStatus(activeProfile(), id)
  if (accept && status?.status !== 'available') {
    throw refusal(409, 'pending_system', `${activeProfile().label} cannot use ${id} yet${status?.note ? `: ${status.note}` : ''}.`)
  }
  const st = store()
  const now = st.acceptedProofSystems.filter((p) => p !== id)
  if (accept) now.push(id)
  // Keep the registry's order, which is the order of preference.
  st.acceptedProofSystems = PROOF_SYSTEMS.map((p) => p.id).filter((p) => now.includes(p))
  return { ok: true, acceptedProofSystems: st.acceptedProofSystems }
})
