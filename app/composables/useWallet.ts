/** What the site is asking the wallet for. `intent` only sets the dialog's title: the same request
 *  creates the account or logs in to it. */
export type WalletPurpose = { kind: 'signin'; intent?: 'signup' | 'login' } | { kind: 'age'; community: string }

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
