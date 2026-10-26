import type { H3Event } from 'h3'

interface BrowserSessionData {
  sid?: string
  pseudonym?: string
  /** Community accounts this browser is logged in to: community slug -> pseudonym. */
  communities?: Record<string, string>
}

/** Cookie session of the browser that shows Community (never the phone). */
export async function browserSession(event: H3Event) {
  const cfg = useRuntimeConfig(event)
  const session = await useSession<BrowserSessionData>(event, {
    name: 'community',
    password: cfg.sessionPassword,
    cookie: { sameSite: 'lax', httpOnly: true, secure: false },
  })
  if (!session.data.sid) await session.update({ sid: crypto.randomUUID() })
  return session
}
