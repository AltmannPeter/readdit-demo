import type { H3Event } from 'h3'

interface BrowserSessionData {
  sid?: string
  pseudonym?: string
}

/** Cookie session of the browser that shows Readdit (never the phone). */
export async function browserSession(event: H3Event) {
  const cfg = useRuntimeConfig(event)
  const session = await useSession<BrowserSessionData>(event, {
    name: 'readdit',
    password: cfg.sessionPassword,
    cookie: { sameSite: 'lax', httpOnly: true, secure: false },
  })
  if (!session.data.sid) await session.update({ sid: crypto.randomUUID() })
  return session
}
