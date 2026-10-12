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

export function getOrCreateAccount(pseudonym: string): { account: AccountRecord; created: boolean } {
  const accounts = store().accounts
  const existing = accounts.get(pseudonym)
  if (existing) return { account: existing, created: false }
  const account: AccountRecord = {
    pseudonym,
    handle: handleFromPseudonym(pseudonym),
    joinedAt: todayISO(),
    birthDateRange: null,
    ageProofs: [],
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
