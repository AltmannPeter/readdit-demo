/** What the site is asking the wallet for. Sign-up and log-in send the same wallet request (the
 *  pseudonym); the site applies it differently: sign-up creates the account or logs in to the
 *  existing one, log-in only logs in to an existing account. A sign-up with `community` (a
 *  logged-out visitor at an age-restricted community) also asks for the community's age range in
 *  the same request, and records it. */
export type WalletPurpose = { kind: 'signin'; intent: 'signup' | 'login'; community?: string } | { kind: 'age'; community: string }

interface WalletState {
  open: boolean
  purpose: WalletPurpose | null
}

/** Opens and closes the wallet connection dialog. */
export function useWallet() {
  const state = useState<WalletState>('wallet', () => ({ open: false, purpose: null }))

  function start(purpose: WalletPurpose) {
    state.value = { open: true, purpose }
  }

  function close() {
    state.value = { open: false, purpose: null }
  }

  return { state, start, close }
}
