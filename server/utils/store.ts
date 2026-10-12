import type { Account, AgeGate } from '#shared/types'
import type { CircuitZkCredentialQuery, CircuitZkFormats, RequestObject, WalletMetadata } from '#shared/types/oid4vp'

export type VpPurpose = { kind: 'signin' } | { kind: 'age'; community: string }

export type VpStatus = 'waiting' | 'scanned' | 'responded' | 'verified' | 'failed' | 'completed'

export type FailReason = 'denied' | 'invalid_request' | 'invalid' | 'unavailable' | 'expired'

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
  outcome?: { ok: true; circuitId: string; pseudonym: string; age?: true } | { ok: false; reason: FailReason; detail?: string }
  completion?: { ok: boolean; kind: 'created' | 'logged_in' | 'age' | 'banned' | 'mismatch' | FailReason; handle?: string }
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

export const SESSION_TTL_MS = 10 * 60_000
