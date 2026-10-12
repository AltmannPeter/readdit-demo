import type { Community } from '#shared/types'

/** login: not signed in. allow / ask / deny: see decideGate. */
export function useCommunityAccess(community: Ref<Community | undefined>) {
  const { account, decide } = useAccount()
  const access = computed<'login' | 'allow' | 'ask' | 'deny'>(() => {
    if (!account.value) return 'login'
    return decide(community.value?.gate ?? null)
  })
  return { access }
}
