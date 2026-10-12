/** What the site is asking the wallet for. */
export type WalletPurpose = { kind: 'signin' } | { kind: 'age'; community: string }

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
