import type { Community } from '#shared/types'

export type CommunityAccess = 'login' | 'ask-signin' | 'allow' | 'ask' | 'deny' | 'join' | 'member-banned'

/** login: not signed in, at a community without an age requirement. ask-signin: not signed in, at
 *  an age-restricted community: one wallet request logs in and proves the age. allow / ask / deny:
 *  see decideGate. A community with its own pseudonym (nymHost) needs its own account, with or
 *  without a Community account: join until this browser has one, member-banned when it is banned. */
export function useCommunityAccess(community: Ref<Community | undefined>) {
  const { account, memberships, decide } = useAccount()
  const access = computed<CommunityAccess>(() => {
    const c = community.value
    if (c?.nymHost) {
      const m = memberships.value[c.slug]
      return !m ? 'join' : m.banned ? 'member-banned' : 'allow'
    }
    if (!account.value) return c?.gate ? 'ask-signin' : 'login'
    return decide(c?.gate ?? null)
  })
  return { access }
}
