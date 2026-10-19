import type { Account, AgeGate, CommunityMembership } from '#shared/types'

interface Me {
  account: Account | null
  bannedHandle: string | null
  /** Community accounts (communities with their own pseudonym) this browser can act as. */
  communities: Record<string, CommunityMembership>
}

/** The logged-in account, kept by the server (GET /api/me). */
export function useAccount() {
  const me = useState<Me>('me', () => ({ account: null, bannedHandle: null, communities: {} }))
  const account = computed(() => me.value.account)
  const memberships = computed(() => me.value.communities ?? {})
  const bannedHandle = computed(() => me.value.bannedHandle)
  const today = useToday()

  async function refresh() {
    const fetcher = import.meta.server ? useRequestFetch() : $fetch
    try {
      me.value = await fetcher<Me>('/api/me')
    } catch {
      /* keep last known state */
    }
  }

  async function signOut() {
    await $fetch('/api/logout', { method: 'POST' })
    me.value = { account: null, bannedHandle: null, communities: {} }
  }

  async function dismissBanNotice() {
    await $fetch('/api/notice', { method: 'DELETE' })
    me.value = { ...me.value, bannedHandle: null }
  }

  function decide(gate: AgeGate | null) {
    if (!gate) return 'allow' as const
    return decideGate(gate, account.value?.birthDateRange ?? null, today.value)
  }

  return { account, bannedHandle, memberships, refresh, signOut, dismissBanNotice, decide }
}
