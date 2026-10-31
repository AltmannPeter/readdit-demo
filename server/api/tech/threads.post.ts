import type { ThreadSetting } from '../../utils/store'

/**
 * /tech's thread setting. Body { threads }: a count from 1 to the machine's cores (maxThreads), or
 * 'all' (one per core); or { parallel }, the old switch (true is 'all', false is 1). Vega, BBS and
 * Longfellow's v0.5 and v0.6 circuits take it on the next prove and verify calls
 * (server/utils/services.ts); Longfellow's v0.4 circuits always run on one thread (Google's runtime
 * directly). A demo reset restores runtime config multithreading. Demo only: no authentication, as
 * /mod. 400 bad_request for anything else.
 */
export default defineEventHandler(async (event) => {
  const body = await readObject<{ parallel: unknown; threads: unknown }>(event)
  const max = maxThreads()
  let t: ThreadSetting
  if (body.threads !== undefined) {
    if (body.threads === 'all') t = 'all'
    else if (typeof body.threads === 'number' && Number.isInteger(body.threads) && body.threads >= 1 && body.threads <= max) t = body.threads
    else throw refusal(400, 'bad_request', `threads must be 'all' or a whole number from 1 to ${max}.`)
  } else if (typeof body.parallel === 'boolean') t = body.parallel ? 'all' : 1
  else throw refusal(400, 'bad_request', 'Give threads (a count, or all) or parallel (a boolean).')
  if (t === max) t = 'all' // the same pool: one thread per core
  store().threads = t
  return { ok: true, multithreading: multithreading(t), threads: t, threadCount: threadCount(t), maxThreads: max }
})
