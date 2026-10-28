import { findCircuit, findScheme } from '#shared/registry/circuits'
import { PROFILES, profileManifest } from '#shared/profiles'

/** Technical view: services and the latest sessions with their traces. */
export default defineEventHandler(async () => {
  const sessions = [...store().sessions.values()].sort((a, b) => b.createdAt - a.createdAt).slice(0, 8)
  const signer = await requestSigner()
  return {
    services: await servicesStatus(),
    // The demo profiles, the active one first in the dropdown's sense: /tech switches between them.
    profile: activeProfile().id,
    profiles: PROFILES.map(profileManifest),
    acceptedProofSystems: store().acceptedProofSystems,
    multithreading: store().multithreading,
    responseMode: store().responseMode,
    profiling: store().profiling,
    trustNewIssuers: store().trustNewIssuers,
    learnedIssuers: (await learnedIssuers()).map(({ key: _key, ...i }) => i),
    measurements: await measurementSummary(),
    signer: { subject: signer.subject, selfSigned: signer.selfSigned },
    sessions: sessions.map((s) => {
      const done = s.outcome?.ok ? s.outcome : undefined
      return {
        id: s.id,
        purpose: s.purpose,
        phone: s.phone ?? null,
        status: s.status,
        createdAt: s.createdAt,
        dcql: s.dcql,
        answered: s.answered ?? null,
        offer: s.offer,
        walletMetadata: s.walletMetadata ?? null,
        tailored: s.tailored ?? false,
        request: s.request ?? null,
        requestJwsBytes: s.requestJwsBytes ?? null,
        circuit: done?.format === 'mso_mdoc' ? (findCircuit(done.proofId) ?? { system_id: done.proofId }) : null,
        scheme: done?.format === 'bbs_cd' ? (findScheme(done.proofId) ?? { system_id: done.proofId }) : null,
        outcome: s.outcome ?? null,
        completion: s.completion ?? null,
        trace: s.trace,
      }
    }),
  }
})
