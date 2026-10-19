import type { Account, AgeGate, BirthDateRange } from '#shared/types'
import type { CredentialQuery, DcqlQuery, RequestObject, VpFormats, WalletMetadata } from '#shared/types/oid4vp'

/**
 * signin: `signup` creates the account; `login` only logs in. With `community` (a logged-out
 * visitor at an age-restricted community) the same request also proves the community's age range,
 * and the completion records it (and creates the account or logs in to it).
 * community: the pseudonym of a community with its own pseudonym (Community.nymHost): creates the
 * community account or logs in to it. With `link` (the person chose "Join and link" while logged
 * in), it also links it to the logged-in Readdit account; logged in, `link` is required (the other
 * choice logs out first).
 */
export type VpPurpose =
  | { kind: 'signin'; intent: 'signup' | 'login'; community?: string }
  | { kind: 'age'; community: string }
  | { kind: 'community'; community: string; link: boolean }

export type VpStatus = 'waiting' | 'scanned' | 'responded' | 'verified' | 'failed' | 'completed'

/** Why a session ended without a verified presentation. `cancelled`: the site's dialog was closed. */
export type FailReason = 'denied' | 'invalid_request' | 'invalid' | 'unavailable' | 'expired' | 'cancelled'

/** How a verified session was applied, or why it was not. */
export type CompletionKind =
  | 'created'
  | 'logged_in'
  | 'age'
  | 'banned'
  | 'mismatch'
  | 'no_account'
  | 'account_exists'
  | 'logged_out'
  /** community: the logged-in account is linked to another pseudonym of this community. */
  | 'other_pseudonym'
  /** community: this community account is linked to another Readdit account. */
  | 'linked_elsewhere'
  | FailReason

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
  /** The DNS name of the verifier identity: client_id x509_san_dns:<host>. */
  host: string
  /** The demo phone on screen (the site's dialog reports swaps), for the technical view. */
  phone?: string
  createdAt: number
  expiresAt: number
  origin: string
  nonce: string
  state: string
  /** The age range the request asks for, if any (from the community's gate, when the session starts). */
  age?: BirthDateRange
  /** The DCQL query: one credential query per accepted format, alternatives in credential_sets.
   *  Made again, with the offer, when the wallet fetches the request, so it follows /tech's switches. */
  dcql: DcqlQuery
  offer: VpFormats
  walletMetadata?: WalletMetadata
  tailored?: boolean
  request?: RequestObject
  requestJwsBytes?: number
  status: VpStatus
  /** The verifier's own timings of this session's presentation, and the time of the call around
   *  it as the response route measures it (round_trip_ms); accepted or refused. */
  verification?: { decode_ms?: number; verify_ms?: number; total_ms?: number; round_trip_ms: number }
  /** The query the wallet answered, once a response arrived. */
  answered?: string
  /** `proofId`: the circuit (circuit_zk) or scheme (mms_zk) of the verified presentation. */
  outcome?: { ok: true; format: CredentialQuery['format']; proofId: string; pseudonym: string; age?: true } | { ok: false; reason: FailReason; detail?: string }
  /** `age`: the session's age proof was recorded for the account. */
  completion?: { ok: boolean; kind: CompletionKind; handle?: string; age?: true; community?: string; linked?: true }
  trace: TraceEvent[]
}

export interface AccountRecord extends Account {
  /** `cascade`: set by the ban of the Readdit account this community account is linked to. */
  banned?: { at: string; reason: string; cascade?: true }
  /** A community account: the community with its own pseudonym. Absent: a Readdit account. */
  community?: string
  /** A community account linked to this Readdit account's pseudonym. */
  linkedTo?: string
  /** The format of the presentation that created the account: circuit_zk (mdoc) or mms_zk (BBS). */
  format?: 'circuit_zk' | 'mms_zk'
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
  /** The proof systems the site accepts now (/tech switches them; a demo reset restores the
   *  configured ones, runtime config acceptedProofSystems). */
  acceptedProofSystems: string[]
}

const g = globalThis as unknown as { __readditStore?: Store }

/** The proof systems accepted at start (runtime config acceptedProofSystems). */
export function configuredProofSystems(): string[] {
  return String(useRuntimeConfig().acceptedProofSystems)
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)
}

function fresh(): Store {
  return { sessions: new Map(), byState: new Map(), accounts: new Map(), comments: [], bannedNotices: new Map(), acceptedProofSystems: configuredProofSystems() }
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
