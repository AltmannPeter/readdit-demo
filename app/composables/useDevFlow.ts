import type { DevAge, DevSession } from '~/dev/flow'

interface DevState {
  session: DevSession | null
  /** The proof systems the site accepts now (/tech). */
  accepted: string[]
  multithreading: boolean
  /** Sessions created up to this time (server clock, ms) are not shown (Clear, R). */
  clearedAt: number
  age: DevAge
  /** The session this view started: the one it completes, and cancels when it is left. */
  ownId: string | null
  starting: boolean
  /** Why the last request did not start. */
  error: string | null
  /** Simulate scan: the mocked phone is on screen and scans the code. */
  phoneShown: boolean
}

const START_ERRORS: Record<string, string> = {
  none_accepted: 'Community accepts no proof system. Switch one on in /tech.',
  unavailable: 'The verifier is not available.',
}

/**
 * The developer view's flow (/dev). It shows this browser's newest session, whichever view
 * started it, from GET /api/dev/latest; it starts its own requests (purpose `dev`: the pseudonym
 * and the chosen age range) and completes them, which creates the Community account or logs in
 * and records the age range.
 */
export function useDevFlow() {
  const state = useState<DevState>('dev-flow', () => ({
    session: null,
    accepted: [],
    multithreading: false,
    clearedAt: 0,
    age: 'none',
    ownId: null,
    starting: false,
    error: null,
    phoneShown: false,
  }))
  const { refresh } = useAccount()
  const { phone } = usePhone()

  const own = computed(() => !!state.value.session && state.value.session.id === state.value.ownId)
  const active = computed(() => {
    const s = state.value.session
    return !!s && (s.status === 'waiting' || s.status === 'scanned' || s.status === 'responded' || s.status === 'verified')
  })

  let completing: string | null = null
  async function load() {
    try {
      const r = await $fetch<{ accepted: string[]; multithreading: boolean; session: DevSession | null }>('/api/dev/latest', { query: { after: state.value.clearedAt } })
      state.value.accepted = r.accepted
      state.value.multithreading = r.multithreading
      state.value.session = r.session
      const s = r.session
      if (s && s.id === state.value.ownId && s.status === 'verified' && completing !== s.id) {
        completing = s.id
        try {
          await $fetch(`/api/vp/session/${s.id}/complete`, { method: 'POST' })
          await refresh()
        } finally {
          completing = null
        }
      }
      if (s && s.id === state.value.ownId && (s.status === 'failed' || s.status === 'completed')) await refresh()
    } catch {
      /* the next poll tries again */
    }
  }

  function cancelOwn() {
    const s = state.value.session
    const id = state.value.ownId
    if (id && s?.id === id && (s.status === 'waiting' || s.status === 'scanned' || s.status === 'responded')) {
      $fetch(`/api/vp/session/${id}/cancel`, { method: 'POST' }).catch(() => {
        /* it expires on its own */
      })
    }
  }

  async function start(age: DevAge = state.value.age) {
    if (state.value.starting) return
    state.value.age = age
    cancelOwn()
    state.value.starting = true
    state.value.error = null
    state.value.phoneShown = false
    try {
      const r = await $fetch<{ id: string }>('/api/vp/session', { method: 'POST', body: { purpose: 'dev', age, origin: window.location.origin, phone: phone.value.label } })
      state.value.ownId = r.id
      await load()
    } catch (e) {
      const code = (e as { data?: { data?: { error?: string } } }).data?.data?.error
      state.value.error = START_ERRORS[code ?? ''] ?? 'The request did not start.'
    } finally {
      state.value.starting = false
    }
  }

  /** Shows the mocked phone, which scans the code at once. */
  function simulateScan() {
    if (own.value && state.value.session?.status === 'waiting') state.value.phoneShown = true
  }

  /** Cancel request (the QR popup). */
  function cancel() {
    cancelOwn()
    state.value.phoneShown = false
  }

  /** Clear (R): cancels a running request and empties the diagram. */
  function reset() {
    cancelOwn()
    // The server's clock: everything up to the session on screen.
    state.value.clearedAt = Math.max(state.value.clearedAt, state.value.session?.createdAt ?? 0)
    state.value.session = null
    state.value.ownId = null
    state.value.error = null
    state.value.phoneShown = false
  }

  return { state, own, active, load, start, simulateScan, cancel, cancelOwn, reset }
}
