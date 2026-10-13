<script setup lang="ts">
import { COMMUNITY_PREFIX } from '#shared/data/communities'

definePageMeta({ layout: false })
useHead({ title: 'Moderation · Readdit' })

interface Overview {
  accounts: Array<{
    pseudonym: string
    handle: string
    joinedAt: string
    ageProofs: Array<{ label: string }>
    banned: { at: string; reason: string } | null
    comments: number
  }>
  comments: Array<{ id: string; handle: string; pseudonym: string; community: string; postTitle: string; body: string; at: number; banned: boolean }>
}

const data = ref<Overview>({ accounts: [], comments: [] })
const confirmReset = ref(false)
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
        <span class="font-bold">readdit</span>
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
          <li v-for="a in data.accounts" :key="a.pseudonym" class="px-5 py-4">
            <div class="flex items-center gap-3">
              <UserAvatar :seed="a.handle" size="sm" />
              <span class="min-w-0 flex-1 truncate text-sm font-semibold">u/{{ a.handle }}</span>
              <button v-if="a.banned" class="btn-ghost" @click="unban(a.pseudonym)">Unban</button>
              <button v-else class="btn-ghost !text-adult" @click="ban(a.pseudonym)">Ban</button>
            </div>
            <dl class="mt-2 space-y-1 text-xs">
              <div class="flex gap-2">
                <dt class="w-20 shrink-0 text-muted">Pseudonym</dt>
                <dd class="font-mono break-all">{{ a.pseudonym }}</dd>
              </div>
              <div class="flex gap-2">
                <dt class="w-20 shrink-0 text-muted">Joined</dt>
                <dd>{{ a.joinedAt }}</dd>
              </div>
              <div class="flex gap-2">
                <dt class="w-20 shrink-0 text-muted">Age checks</dt>
                <dd>{{ a.ageProofs.map((p) => p.label).join(', ') || 'None' }}</dd>
              </div>
              <div class="flex gap-2">
                <dt class="w-20 shrink-0 text-muted">Status</dt>
                <dd :class="a.banned ? 'font-semibold text-adult' : ''">{{ a.banned ? `Banned (${a.banned.reason})` : 'Active' }}</dd>
              </div>
            </dl>
          </li>
        </ul>
      </section>
    </main>
  </div>
</template>
