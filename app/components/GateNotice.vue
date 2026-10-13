<script setup lang="ts">
import type { Community } from '#shared/types'
import { COMMUNITY_PREFIX } from '#shared/data/communities'

const props = defineProps<{ community: Community; state: 'login' | 'ask-signin' | 'ask' | 'deny' }>()
const wallet = useWallet()

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
    <template v-if="props.state === 'ask' || props.state === 'ask-signin'">
      <span class="flex size-12 items-center justify-center rounded-full bg-brand-soft text-brand">
        <AppIcon name="shield" class="size-6" />
      </span>
      <h2 class="mt-4 text-lg font-semibold">{{ name }} is {{ ageText }}</h2>
      <p class="mt-1 max-w-sm text-sm text-muted">
        Prove your age with your wallet to enter. Readdit learns whether you meet the requirement, not your date of birth.
      </p>
      <p v-if="props.state === 'ask-signin'" class="mt-2 max-w-sm text-sm text-muted">The same step logs you in to Readdit with a pseudonym.</p>
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
