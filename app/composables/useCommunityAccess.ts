import type { Community } from '#shared/types'

export type CommunityAccess = 'login' | 'ask-signin' | 'allow' | 'ask' | 'deny'

/** login: not signed in, at a community without an age requirement. ask-signin: not signed in, at
 *  an age-restricted community: one wallet request logs in and proves the age. allow / ask / deny:
 *  see decideGate. */
export function useCommunityAccess(community: Ref<Community | undefined>) {
  const { account, decide } = useAccount()
  const access = computed<CommunityAccess>(() => {
    if (!account.value) return community.value?.gate ? 'ask-signin' : 'login'
    return decide(community.value?.gate ?? null)
  })
  return { access }
}
