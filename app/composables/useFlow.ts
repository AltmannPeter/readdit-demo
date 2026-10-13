import type { ConsentView, RequestView } from '~/wallet/engine'
import type { WalletPurpose } from './useWallet'

// The state of a wallet request as the wallet and the site's dialog see it. Both publish here,
// and the guide panel derives its current step from it (app/guide/steps.ts).

export type WalletScreen = 'home' | 'detail' | 'presentations' | 'scan' | 'request' | 'unmet' | 'pin' | 'working' | 'done' | 'declined' | 'error'

export interface ProofMetrics {
  sign_ms?: number
  witness_ms?: number
  prove_ms?: number
  proof_bytes?: number
  presentation_bytes?: number
  simulated?: boolean
}

/** What the wallet on the phone shows and knows about the current request. */
export interface WalletFlow {
  screen: WalletScreen
  /** The PIN screen shows "incorrect pin". */
  pinRejected: boolean
  /** Circuits the wallet can run (its wallet_metadata). */
  walletCircuits: string[]
  view: RequestView | null
  consent: ConsentView | null
  metrics: ProofMetrics | null
  /** The error the wallet sent to response_uri when it refused. */
  sentError: 'access_denied' | 'invalid_request' | null
  error: { title: string; description: string } | null
}

export type DialogPhase = 'starting' | 'waiting' | 'scanned' | 'verifying' | 'success' | 'failed'

/** The site's cross-device dialog: the QR code and the session's outcome. */
export interface DialogFlow {
  phase: DialogPhase
  authUrl: string | null
  failure: string | null
  completion: { kind: string; handle?: string } | null
}

/** The last wallet request that ended, kept until the page changes. */
export interface LastOutcome {
  purpose: WalletPurpose
  ok: boolean
  kind: string
  handle?: string
}

export const initialWalletFlow = (): WalletFlow => ({
  screen: 'home',
  pinRejected: false,
  walletCircuits: [],
  view: null,
  consent: null,
  metrics: null,
  sentError: null,
  error: null,
})

export const useWalletFlow = () => useState<WalletFlow>('flow-wallet', initialWalletFlow)

export const useDialogFlow = () =>
  useState<DialogFlow>('flow-dialog', () => ({ phase: 'starting', authUrl: null, failure: null, completion: null }))

export const useLastOutcome = () => useState<LastOutcome | null>('flow-last', () => null)
