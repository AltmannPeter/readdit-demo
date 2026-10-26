// The mocked phone reports its own steps (verifier authenticated, attestation matched, the holder's
// answer, the response encrypted) to the site's trace of the session, for the developer view and
// /tech. A real wallet does not; its steps then do not show. Best effort: a failed report changes
// nothing in the flow.

export type WalletStep = 'authenticate' | 'match' | 'consent' | 'decline' | 'encrypt'

export async function report(state: string | undefined, step: WalletStep, label: string, data?: Record<string, unknown>): Promise<void> {
  if (!state) return
  try {
    await $fetch('/api/wallet/trace', { method: 'POST', body: { state, step, label, ...(data && { data }) } })
  } catch {
    /* the trace is for the technical views only */
  }
}
