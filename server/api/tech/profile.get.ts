/** One Benchmark row's profiles, for /tech when its time is opened: ?row=<the row's key>. */
export default defineEventHandler(async (event) => {
  const row = getQuery(event).row
  if (typeof row !== 'string' || !row) throw refusal(400, 'bad_request', 'row is required.')
  return rowProfile(row)
})
