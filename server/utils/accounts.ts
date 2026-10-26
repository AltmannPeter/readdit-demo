import type { AgeGate } from '#shared/types'
import type { AccountRecord } from './store'
import { gateLabel, gateRange, intersectRanges, todayISO } from '#shared/utils/age'
import { handleFromPseudonym } from '#shared/utils/handle'

export function publicAccount(a: AccountRecord) {
  return {
    pseudonym: a.pseudonym,
    handle: a.handle,
    joinedAt: a.joinedAt,
    birthDateRange: a.birthDateRange,
    ageProofs: a.ageProofs,
  }
}

/** The Community account of a pseudonym; never a community account. */
export function mainAccount(pseudonym: string | undefined): AccountRecord | undefined {
  const a = pseudonym ? store().accounts.get(pseudonym) : undefined
  return a && !a.community ? a : undefined
}

/** The community account of a pseudonym in `community`. */
export function communityAccount(community: string, pseudonym: string | undefined): AccountRecord | undefined {
  const a = pseudonym ? store().accounts.get(pseudonym) : undefined
  return a?.community === community ? a : undefined
}

/** The community account in `community` linked to the Community account `main`. */
export function linkedCommunityAccount(community: string, main: string): AccountRecord | undefined {
  for (const a of store().accounts.values()) if (a.community === community && a.linkedTo === main) return a
  return undefined
}

/**
 * The community account a browser acts as in `community`. With a Community account logged in, only
 * the community account linked to it: an unlinked one needs a new presentation, which links it.
 * Otherwise the community account the browser logged in to. Banned accounts included; the caller
 * decides.
 */
export function memberAccount(community: string, data: { pseudonym?: string; communities?: Record<string, string> }): AccountRecord | undefined {
  const main = mainAccount(data.pseudonym)
  if (main && !main.banned) return linkedCommunityAccount(community, main.pseudonym)
  return communityAccount(community, data.communities?.[community])
}

/**
 * The account of a pseudonym, created when new. Pseudonyms of different verifier identities never
 * coincide, so Community and community accounts share one map; `community` marks the latter.
 */
export function getOrCreateAccount(pseudonym: string, community?: string, format?: AccountRecord['format']): { account: AccountRecord; created: boolean } {
  const accounts = store().accounts
  const existing = accounts.get(pseudonym)
  if (existing) return { account: existing, created: false }
  const account: AccountRecord = {
    pseudonym,
    handle: handleFromPseudonym(pseudonym),
    joinedAt: todayISO(),
    birthDateRange: null,
    ageProofs: [],
    ...(community && { community }),
    ...(format && { format }),
  }
  accounts.set(pseudonym, account)
  return { account, created: true }
}

export function recordAgeProof(a: AccountRecord, gate: AgeGate) {
  const today = todayISO()
  const range = gateRange(gate, today)
  a.birthDateRange = intersectRanges(a.birthDateRange, range)
  a.ageProofs.push({ label: gateLabel(gate), range, at: today })
}
