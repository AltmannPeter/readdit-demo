<script setup lang="ts">
import { COMMUNITY_PREFIX } from '#shared/data/communities'
import type { ModAccountRow } from '~/components/ModAccount.vue'

definePageMeta({ layout: false })
useHead({ title: 'Moderation · Community' })

interface Overview {
  accounts: ModAccountRow[]
  comments: Array<{ id: string; handle: string; pseudonym: string; community: string; postTitle: string; body: string; at: number; banned: boolean }>
}

const data = ref<Overview>({ accounts: [], comments: [] })
const confirmReset = ref(false)
/** Community accounts with their linked community accounts under them; unlinked community accounts on their own. */
const groups = computed(() => {
  const mains = new Set(data.value.accounts.filter((a) => !a.community).map((a) => a.handle))
  const nested = (a: ModAccountRow) => !!a.community && !!a.linkedTo && mains.has(a.linkedTo)
  return data.value.accounts
    .filter((a) => !nested(a))
    .map((a) => ({ account: a, linked: a.community ? [] : data.value.accounts.filter((c) => nested(c) && c.linkedTo === a.handle) }))
})
const load = async () => {
  try {
    data.value = await $fetch<Overview>('/api/mod/overview')
  } catch {
    /* the next poll tries again */
  }
}
let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  load()
  timer = setInterval(load, 1500)
})
onBeforeUnmount(() => clearInterval(timer))

async function ban(pseudonym: string) {
  await $fetch('/api/mod/ban', { method: 'POST', body: { pseudonym } })
  await load()
}
async function unban(pseudonym: string) {
  await $fetch('/api/mod/unban', { method: 'POST', body: { pseudonym } })
  await load()
}
async function reset() {
  if (!confirmReset.value) {
    confirmReset.value = true
    setTimeout(() => (confirmReset.value = false), 3000)
    return
  }
  confirmReset.value = false
  await $fetch('/api/demo/reset', { method: 'POST' })
  await load()
}
const time = (t: number) => new Date(t).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
</script>

<template>
  <div class="min-h-screen bg-canvas">
    <header class="border-b border-line bg-surface">
      <div class="mx-auto flex h-14 max-w-5xl items-center gap-3 px-6">
        <AppLogo class="size-7" />
        <span class="font-bold">community</span>
        <span class="text-muted">·</span>
        <span class="font-semibold">Moderation</span>
        <button class="ml-auto text-xs font-semibold text-muted hover:text-adult" @click="reset">
          {{ confirmReset ? 'Click again to reset the demo' : 'Reset demo' }}
        </button>
      </div>
    </header>

    <main class="mx-auto grid max-w-5xl gap-6 px-6 py-6 lg:grid-cols-[3fr_2fr]">
      <section class="card">
        <h2 class="border-b border-line px-5 py-3 text-sm font-semibold">Recent comments</h2>
        <p v-if="!data.comments.length" class="px-5 py-8 text-center text-sm text-muted">No comments yet.</p>
        <ul class="divide-y divide-line">
          <li v-for="c in data.comments" :key="c.id" class="flex gap-4 px-5 py-4" :class="c.banned && 'opacity-50'">
            <div class="min-w-0 flex-1">
              <p class="text-xs text-muted">
                <span class="font-semibold text-ink">u/{{ c.handle }}</span> in {{ COMMUNITY_PREFIX }}{{ c.community }} · {{ time(c.at) }}
              </p>
              <p class="mt-0.5 truncate text-xs text-muted">On: {{ c.postTitle }}</p>
              <p class="mt-1.5 text-sm">{{ c.body }}</p>
            </div>
            <span v-if="c.banned" class="self-start text-xs font-semibold text-adult">Banned</span>
            <button v-else class="btn-outline self-start !border-adult !text-adult hover:!bg-adult/10" @click="ban(c.pseudonym)">
              Ban user
            </button>
          </li>
        </ul>
      </section>

      <section class="card self-start">
        <h2 class="border-b border-line px-5 py-3 text-sm font-semibold">Accounts</h2>
        <p v-if="!data.accounts.length" class="px-5 py-8 text-center text-sm text-muted">No accounts yet.</p>
        <ul class="divide-y divide-line">
          <li v-for="g in groups" :key="g.account.pseudonym" class="px-5 py-4">
            <ModAccount :account="g.account" @ban="ban" @unban="unban" />
            <div v-if="g.linked.length" class="mt-3 ml-3 space-y-3 border-l-2 border-line pl-4">
              <p class="text-[11px] font-semibold tracking-wide text-muted uppercase">Linked</p>
              <ModAccount v-for="c in g.linked" :key="c.pseudonym" :account="c" nested @ban="ban" @unban="unban" />
            </div>
          </li>
        </ul>
      </section>
    </main>
  </div>
</template>
