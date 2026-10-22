<script setup lang="ts">
import type { Community } from '#shared/types'
import { COMMUNITY_PREFIX } from '#shared/data/communities'

const props = defineProps<{ community: Community; state: 'login' | 'ask-signin' | 'ask' | 'deny' | 'join' | 'member-banned' }>()
const wallet = useWallet()
const { account, memberships, signOut } = useAccount()

/** Logged in, joining is a choice: link the new account to this one, or log out and join separately. */
function join(link: boolean) {
  wallet.start({ kind: 'community', community: props.community.slug, link })
}
async function logOutAndJoin() {
  await signOut()
  join(false)
}

const name = computed(() => `${COMMUNITY_PREFIX}${props.community.slug}`)
const ageText = computed(() => {
  const g = props.community.gate
  if (!g) return ''
  if (g.minAge != null && g.maxAge != null) return `for ages ${g.minAge} to ${g.maxAge}`
  if (g.minAge != null) return `for ages ${g.minAge} and older`
  return `for ages under ${g.maxAge! + 1}`
})
</script>

<template>
  <LoginNotice v-if="props.state === 'login'" :title="`Log in to view ${name}`" />
  <div v-else class="card flex flex-col items-center px-6 py-12 text-center">
    <template v-if="props.state === 'join'">
      <span class="flex size-12 items-center justify-center rounded-full bg-brand-soft text-brand">
        <AppIcon name="user" class="size-6" />
      </span>
      <h2 class="mt-4 text-lg font-semibold">{{ name }} asks for proof of human</h2>
      <div class="mt-3 max-w-md space-y-2 text-left text-sm text-muted">
        <p>Prove with your wallet that you are a real person. You get a pseudonym for {{ name }} only, which is not linked to your other accounts unless you choose to. One account per person.</p>
        <p v-if="account">
          You are logged in as u/{{ account.handle }}. Linking tells Community that both accounts are yours. To keep them apart, log out
          first.
        </p>
      </div>
      <div v-if="account" class="mt-5 flex flex-wrap justify-center gap-2">
        <button class="btn-outline" @click="logOutAndJoin">Log out and join separately</button>
        <button class="btn-primary" @click="join(true)">Join and link to u/{{ account.handle }}</button>
      </div>
      <button v-else class="btn-primary mt-5" @click="join(false)">Join with wallet</button>
    </template>

    <template v-else-if="props.state === 'member-banned'">
      <span class="flex size-12 items-center justify-center rounded-full bg-adult/10 text-adult">
        <AppIcon name="ban" class="size-6" />
      </span>
      <h2 class="mt-4 text-lg font-semibold">Your {{ name }} account is banned</h2>
      <p v-if="memberships[props.community.slug]?.bannedWith" class="mt-1 max-w-sm text-sm text-muted">
        It is linked to u/{{ memberships[props.community.slug]?.bannedWith }}, and a moderator banned that Community account.
      </p>
      <p v-else class="mt-1 max-w-sm text-sm text-muted">A moderator banned u/{{ memberships[props.community.slug]?.handle }} in {{ name }}.</p>
      <NuxtLink to="/" class="btn-outline mt-5">Back to Home</NuxtLink>
    </template>

    <template v-else-if="props.state === 'ask' || props.state === 'ask-signin'">
      <span class="flex size-12 items-center justify-center rounded-full bg-brand-soft text-brand">
        <AppIcon name="shield" class="size-6" />
      </span>
      <h2 class="mt-4 text-lg font-semibold">{{ name }} is {{ ageText }}</h2>
      <p class="mt-1 max-w-sm text-sm text-muted">
        Prove your age with your wallet to enter. Community learns whether you meet the requirement, not your date of birth.
      </p>
      <p v-if="props.state === 'ask-signin'" class="mt-2 max-w-sm text-sm text-muted">The same step logs you in to Community with a pseudonym.</p>
      <button
        class="btn-primary mt-5"
        @click="
          wallet.start(
            props.state === 'ask-signin'
              ? { kind: 'signin', intent: 'signup', community: props.community.slug }
              : { kind: 'age', community: props.community.slug },
          )
        "
      >
        Verify age with wallet
      </button>
    </template>

    <template v-else>
      <span class="flex size-12 items-center justify-center rounded-full bg-adult/10 text-adult">
        <AppIcon name="ban" class="size-6" />
      </span>
      <h2 class="mt-4 text-lg font-semibold">You can't enter {{ name }}</h2>
      <p class="mt-1 max-w-sm text-sm text-muted">This community is {{ ageText }}. Your verified age does not meet this requirement.</p>
      <NuxtLink to="/" class="btn-outline mt-5">Back to Home</NuxtLink>
    </template>
  </div>
</template>
