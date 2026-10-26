import { FAULT_STEPS, type FaultStep, armFault, testFaultsEnabled } from '../../utils/test-faults'

/** Test only (COMMUNITY_TEST_FAULTS=1): arm one failure of the next addon call of `step` (or `issuer.read`, server/utils/test-faults.ts). 404 otherwise. */
export default defineEventHandler(async (event) => {
  if (!testFaultsEnabled()) throw createError({ statusCode: 404 })
  const body = (await readBody<{ step?: string }>(event)) ?? {}
  if (!FAULT_STEPS.includes(body.step as FaultStep)) {
    throw createError({ statusCode: 400, statusMessage: `step must be one of ${FAULT_STEPS.join(', ')}.`, data: { error: 'bad_request' } })
  }
  armFault(body.step as FaultStep)
  return { armed: body.step }
})
