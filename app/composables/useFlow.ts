import type { ConsentView, RequestView } from '~/wallet/engine'
import type { CredentialView } from '~/wallet/holder'
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
}

/** What the wallet on the phone shows and knows about the current request. */
export interface WalletFlow {
  /** The phone the wallet runs on ("Teen's phone"). */
  phone: string
  screen: WalletScreen
  /** The credential in focus: the one whose details are open, or the one the request uses. */
  credential: CredentialView | null
  /** How many of the wallet's credentials match the current request. */
  matching: number
  /** The "Switch credential" popup is open. */
  switching: boolean
  /** Circuits the wallet can run (its wallet_metadata). */
  walletCircuits: string[]
  view: RequestView | null
  consent: ConsentView | null
  metrics: ProofMetrics | null
  /** The error the wallet sent to response_uri when it refused. */
  sentError: 'access_denied' | 'invalid_request' | null
  /** Where the person declined: on the request screen, or at the PIN. */
  declinedAt: 'request' | 'pin' | null
  /** The error screen, and its technical cause for the guide: "request_uri 410 already_used". */
  error: { title: string; description: string; cause?: string } | null
}

export type DialogPhase = 'starting' | 'waiting' | 'scanned' | 'verifying' | 'success' | 'failed'

/** The verifier's timings of the presentation, as the server measured them (GET /api/vp/session/:id). */
export interface VerificationMetrics {
  decode_ms?: number
  verify_ms?: number
  total_ms?: number
  /** The verifier call as the response route timed it, around decoding and verification. */
  round_trip_ms: number
}

/** The site's cross-device dialog: the QR code and the session's outcome. */
export interface DialogFlow {
  phase: DialogPhase
  authUrl: string | null
  failure: string | null
  completion: { kind: string; handle?: string; age?: boolean; community?: string; linked?: boolean } | null
  /** The phone was swapped while this request's QR code was on screen. */
  swapped: boolean
  verification: VerificationMetrics | null
}

/** The last wallet request that ended, kept until the page changes. `closed`: the dialog was
 *  closed before the request ended. */
export interface LastOutcome {
  purpose: WalletPurpose
  ok: boolean
  kind: string
  handle?: string
}

export const initialWalletFlow = (): WalletFlow => ({
  phone: '',
  screen: 'home',
  credential: null,
  matching: 0,
  switching: false,
  walletCircuits: [],
  view: null,
  consent: null,
  metrics: null,
  sentError: null,
  declinedAt: null,
  error: null,
})

export const useWalletFlow = () => useState<WalletFlow>('flow-wallet', initialWalletFlow)

export const useDialogFlow = () =>
  useState<DialogFlow>('flow-dialog', () => ({ phase: 'starting', authUrl: null, failure: null, completion: null, verification: null, swapped: false }))

export const useLastOutcome = () => useState<LastOutcome | null>('flow-last', () => null)
