/**
 * The Benchmark over a window of runs (scripts/bench.mjs): `?since=<ISO time>` keeps the records
 * made at or after it, in the active demo profile, grouped and summarised exactly as /tech's
 * Benchmark (server/utils/measurements.ts); without it, every record of the profile. `&raw=1` adds
 * the records themselves (`records`). Read-only. 400 bad_request for a `since` that is not a time.
 */
export default defineEventHandler(async (event) => {
  const q = getQuery(event)
  const since = typeof q.since === 'string' && q.since ? q.since : undefined
  if (since !== undefined && Number.isNaN(Date.parse(since))) throw refusal(400, 'bad_request', 'since must be an ISO time.')
  const summary = await measurementSummary({ since })
  if (!q.raw) return summary
  const records = measurements().filter((m) => profileOfRecord(m) === summary.profile && (!since || m.at >= since))
  return { ...summary, records }
})
