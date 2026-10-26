/**
 * Developer view: this browser's newest session (from the developer view or from the Community
 * dialog), with its trace, request and decrypted response, and the proof systems the site accepts
 * now (/tech). `?after=<ms>`: only a session created after that time (the view's Clear).
 */
export default defineEventHandler(async (event) => {
  const b = await browserSession(event)
  const after = Number(getQuery(event).after) || 0
  const mine = [...store().sessions.values()].filter((s) => s.ownerSid === b.data.sid && s.createdAt > after).sort((a, b) => b.createdAt - a.createdAt)
  const latest = mine[0] ? getVpSession(mine[0].id) : undefined
  return {
    accepted: store().acceptedProofSystems,
    multithreading: store().multithreading,
    session: latest ? await devSessionView(latest) : null,
  }
})
