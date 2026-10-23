import type { Account, AgeGate, BirthDateRange } from '#shared/types'
import type { DcqlQuery, RequestObject, SourceFormat, VpFormats, WalletMetadata } from '#shared/types/oid4vp'
import type { ResponseKey } from './response-key'
import type { SizePart, StepProfile } from './services'

/**
 * signin: `signup` creates the account; `login` only logs in. With `community` (a logged-out
 * visitor at an age-restricted community) the same request also proves the community's age range,
 * and the completion records it (and creates the account or logs in to it).
 * community: the pseudonym of a community with its own pseudonym (Community.nymHost): creates the
 * community account or logs in to it. With `link` (the person chose "Link to u/…" while logged
 * in), it also links it to the logged-in Community account; logged in, `link` is required (the other
 * choice logs out first).
 */
export type VpPurpose =
  | { kind: 'signin'; intent: 'signup' | 'login'; community?: string }
  /** The developer view's request: the pseudonym, and the age range when one is chosen. Creates
   *  the account or logs in to it, and records the age range. */
  | { kind: 'dev'; age: DevAge }
  | { kind: 'age'; community: string }
  | { kind: 'community'; community: string; link: boolean }

/** The developer view's age options: none, 18 or older, 13 to 17. */
export type DevAge = 'none' | 'over18' | 'range13to17'
export const DEV_GATES: Record<DevAge, AgeGate | undefined> = { none: undefined, over18: { minAge: 18 }, range13to17: { minAge: 13, maxAge: 17 } }

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
  /** community: this community account is linked to another Community account. */
  | 'linked_elsewhere'
  | FailReason

export interface TraceEvent {
  at: number
  step: string
  label: string
  data?: Record<string, unknown>
}

export interface SessionDetail {
  profiles: Partial<Record<'sign' | 'witness' | 'prove' | 'verify', StepProfile>>
  proofParts?: SizePart[] | null
  presentationParts?: SizePart[] | null
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
  /** The key the wallet encrypts its response to (direct_post.jwt). Not in any trace or API answer. */
  responseKey: ResponseKey
  /** The age range the request asks for, if any (from the community's gate, when the session starts). */
  age?: BirthDateRange
  /** The DCQL query: one zkp_req credential query per source format the accepted systems cover,
   *  alternatives in credential_sets.
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
  /** The decrypted response, for the developer view: its JWE header and size, and the presentation. */
  response?: { jwe: { header: Record<string, unknown>; bytes: number }; presentation?: string }
  /** The query the wallet answered, once a response arrived. */
  answered?: string
  /** `format`: the source format of the answered query; `proofId`: the system (circuit or scheme)
   *  of the verified presentation. */
  outcome?: { ok: true; format: SourceFormat; proofId: string; pseudonym: string; age?: true } | { ok: false; reason: FailReason; detail?: string }
  /** `age`: the session's age proof was recorded for the account. */
  completion?: { ok: boolean; kind: CompletionKind; handle?: string; age?: true; community?: string; linked?: true }
  trace: TraceEvent[]
  /** For /tech's Benchmark only, never in a trace or an API answer about the session: the
   *  profiles of this presentation's steps (Profiling on), and the bytes of its proof and
   *  presentation by part. */
  detail?: SessionDetail
}

export interface AccountRecord extends Account {
  /** `cascade`: set by the ban of the Community account this community account is linked to. */
  banned?: { at: string; reason: string; cascade?: true }
  /** A community account: the community with its own pseudonym. Absent: a Community account. */
  community?: string
  /** A community account linked to this Community account's pseudonym. */
  linkedTo?: string
  /** The source format of the presentation that created the account: mso_mdoc or bbs_cd (BBS). */
  format?: SourceFormat
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
  /** Vega and BBS on every core (/tech's switch; a demo reset restores runtime config multithreading). */
  multithreading: boolean
  /** /tech's Profiling switch: the addons sample their steps (off at start and after a demo reset). */
  profiling: boolean
}

const g = globalThis as unknown as { __communityStore?: Store }

/** The proof systems accepted at start (runtime config acceptedProofSystems). */
export function configuredProofSystems(): string[] {
  return String(useRuntimeConfig().acceptedProofSystems)
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)
}

/** Whether Vega and BBS run on every core at start (runtime config multithreading). */
export function configuredMultithreading(): boolean {
  const v = useRuntimeConfig().multithreading as unknown
  return v === true || v === 'true' || v === '1'
}

function fresh(): Store {
  return {
    sessions: new Map(),
    byState: new Map(),
    accounts: new Map(),
    comments: [],
    bannedNotices: new Map(),
    acceptedProofSystems: configuredProofSystems(),
    multithreading: configuredMultithreading(),
    profiling: false,
  }
}

/** In-memory demo state. Survives hot reload, not restarts. */
export function store(): Store {
  g.__communityStore ??= fresh()
  return g.__communityStore
}

export function resetStore() {
  g.__communityStore = fresh()
}

export function addTrace(s: VpSessionRecord, step: string, label: string, data?: Record<string, unknown>) {
  s.trace.push({ at: Date.now(), step, label, ...(data && { data }) })
}

/** How long a wallet request stays valid (runtime config vpSessionTtlS, NUXT_VP_SESSION_TTL_S). */
export function sessionTtlMs(): number {
  const s = Number(useRuntimeConfig().vpSessionTtlS)
  return (Number.isFinite(s) && s > 0 ? s : 600) * 1000
}
