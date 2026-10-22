// Test-only fault injection, for driving the "backend failing" path end to end
// (scripts/flows-check.mjs). It exists only when the server starts with COMMUNITY_TEST_FAULTS=1:
// then POST /api/test/fault { step } arms one failure of the next addon call of that step, and
// services.ts fails that call as if the addon had thrown. Without the variable the route answers
// 404 and no call is ever failed.

export const FAULT_STEPS = ['prover.info', 'prover.sign', 'prover.prove', 'verifier.info', 'verifier.verify'] as const
export type FaultStep = (typeof FAULT_STEPS)[number]

const g = globalThis as unknown as { __communityFaults?: Partial<Record<FaultStep, number>> }

export const testFaultsEnabled = () => process.env.COMMUNITY_TEST_FAULTS === '1'

export function armFault(step: FaultStep) {
  g.__communityFaults ??= {}
  g.__communityFaults[step] = (g.__communityFaults[step] ?? 0) + 1
}

/** True once per armed fault of this step; always false without COMMUNITY_TEST_FAULTS=1. */
export function takeFault(step: FaultStep): boolean {
  if (!testFaultsEnabled()) return false
  const left = g.__communityFaults?.[step] ?? 0
  if (left < 1) return false
  g.__communityFaults![step] = left - 1
  return true
}
