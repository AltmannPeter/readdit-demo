<script setup lang="ts">
import { COMMUNITY_PREFIX } from '#shared/data/communities'

// The account in the header: the Community account, or, without one, the community account this
// browser joined with (a community with its own pseudonym), marked with its community.
const { account, memberships, signOut } = useAccount()
const wallet = useWallet()
const open = ref(false)

const joined = computed(() => Object.entries(memberships.value).filter(([, m]) => !m.banned))
const shown = computed(() => {
  if (account.value) return { handle: account.value.handle, community: null as string | null }
  const first = joined.value[0]
  return first ? { handle: first[1].handle, community: first[0] } : null
})

async function logOut() {
  open.value = false
  await signOut()
  await navigateTo('/')
}
function logIn() {
  open.value = false
  wallet.start({ kind: 'signin', intent: 'login' })
}
</script>

<template>
  <div v-if="shown" class="relative">
    <button
      class="flex items-center gap-2 rounded-full py-1 pr-2 pl-1 hover:bg-canvas"
      :aria-expanded="open"
      @click="open = !open"
    >
      <UserAvatar :seed="shown.handle" size="sm" />
      <span class="hidden text-sm font-medium sm:inline">u/{{ shown.handle }}</span>
      <span v-if="shown.community" class="rounded bg-brand/10 px-1.5 py-0.5 text-[11px] font-semibold text-brand">{{ COMMUNITY_PREFIX }}{{ shown.community }}</span>
      <AppIcon name="chevron" class="size-4 text-muted" />
    </button>

    <template v-if="open">
      <div class="fixed inset-0 z-40" @click="open = false" />
      <div class="card absolute right-0 z-50 mt-2 w-72 p-2 shadow-lg">
        <div class="px-3 py-2">
          <p class="text-sm font-semibold">u/{{ shown.handle }}</p>
          <p class="mt-0.5 text-xs text-muted">{{ shown.community ? `${COMMUNITY_PREFIX}${shown.community} account only, no Community account` : 'Pseudonymous account' }}</p>
        </div>
        <template v-if="account && joined.length">
          <hr class="my-1 border-line" />
          <div v-for="[slug, m] in joined" :key="slug" class="px-3 py-1.5 text-xs">
            <span class="font-medium">{{ COMMUNITY_PREFIX }}{{ slug }}</span>
            <span class="text-muted"> · u/{{ m.handle }}</span>
          </div>
        </template>
        <hr class="my-1 border-line" />
        <button v-if="!account" class="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm hover:bg-canvas" @click="logIn">
          <AppIcon name="user" class="size-4 text-muted" />
          Log in to Community
        </button>
        <button class="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm hover:bg-canvas" @click="logOut">
          <AppIcon name="logout" class="size-4 text-muted" />
          Log out
        </button>
      </div>
    </template>
  </div>
</template>
