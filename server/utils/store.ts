import type { Account, AgeGate } from '#shared/types'
import type { CircuitZkCredentialQuery, CircuitZkFormats, RequestObject, WalletMetadata } from '#shared/types/oid4vp'

/**
 * signin: `signup` creates the account or logs in to an existing one; `login` only logs in. With
 * `community` (a logged-out visitor at an age-restricted community) the same request also proves
 * the community's age range, and the completion records it.
 */
export type VpPurpose = { kind: 'signin'; intent: 'signup' | 'login'; community?: string } | { kind: 'age'; community: string }

export type VpStatus = 'waiting' | 'scanned' | 'responded' | 'verified' | 'failed' | 'completed'

/** Why a session ended without a verified presentation. `cancelled`: the site's dialog was closed. */
export type FailReason = 'denied' | 'invalid_request' | 'invalid' | 'unavailable' | 'expired' | 'cancelled'

/** How a verified session was applied, or why it was not. */
export type CompletionKind = 'created' | 'logged_in' | 'age' | 'banned' | 'mismatch' | 'no_account' | 'logged_out' | FailReason

export interface TraceEvent {
  at: number
  step: string
  label: string
  data?: Record<string, unknown>
}

export interface VpSessionRecord {
  id: string
  purpose: VpPurpose
  gate?: AgeGate
  ownerSid: string
  createdAt: number
  expiresAt: number
  origin: string
  nonce: string
  state: string
  query: CircuitZkCredentialQuery
  offer: CircuitZkFormats
  walletMetadata?: WalletMetadata
  tailored?: boolean
  request?: RequestObject
  requestJwsBytes?: number
  status: VpStatus
  /** The verifier's own timings of this session's presentation, and the time of the call around
   *  it as the response route measures it (round_trip_ms); accepted or refused. */
  verification?: { decode_ms?: number; verify_ms?: number; total_ms?: number; round_trip_ms: number }
  outcome?: { ok: true; circuitId: string; pseudonym: string; age?: true } | { ok: false; reason: FailReason; detail?: string }
  /** `age`: the session's age proof was recorded for the account. */
  completion?: { ok: boolean; kind: CompletionKind; handle?: string; age?: true }
  trace: TraceEvent[]
}

export interface AccountRecord extends Account {
  banned?: { at: string; reason: string }
}

export interface UserComment {
  id: string
  postId: string
  community: string
  pseudonym: string
  handle: string
  body: string
  at: number
}

interface Store {
  sessions: Map<string, VpSessionRecord>
  byState: Map<string, string>
  accounts: Map<string, AccountRecord>
  comments: UserComment[]
  /** Browser sessions logged out by a ban, so the UI can say why. */
  bannedNotices: Map<string, string>
}

const g = globalThis as unknown as { __readditStore?: Store }

function fresh(): Store {
  return { sessions: new Map(), byState: new Map(), accounts: new Map(), comments: [], bannedNotices: new Map() }
}

/** In-memory demo state. Survives hot reload, not restarts. */
export function store(): Store {
  g.__readditStore ??= fresh()
  return g.__readditStore
}

export function resetStore() {
  g.__readditStore = fresh()
}

export function addTrace(s: VpSessionRecord, step: string, label: string, data?: Record<string, unknown>) {
  s.trace.push({ at: Date.now(), step, label, ...(data && { data }) })
}

/** How long a wallet request stays valid (runtime config vpSessionTtlS, NUXT_VP_SESSION_TTL_S). */
export function sessionTtlMs(): number {
  const s = Number(useRuntimeConfig().vpSessionTtlS)
  return (Number.isFinite(s) && s > 0 ? s : 600) * 1000
}
