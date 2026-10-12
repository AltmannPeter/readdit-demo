<script setup lang="ts">
import { findCommunity, COMMUNITY_PREFIX } from '#shared/data/communities'

// Site side of the cross-device flow. The server owns the OpenID4VP session and runs
// the verifier; this dialog shows the QR code, follows the status and applies the result
// to this browser's login.

type Phase = 'starting' | 'waiting' | 'scanned' | 'verifying' | 'success' | 'failed'

interface Completion {
  ok: boolean
  kind: string
  handle?: string
}

const { state, close } = useWallet()
const { refresh } = useAccount()
const siteName = useRuntimeConfig().public.siteName as string

const sessionId = ref<string | null>(null)
const authUrl = ref<string | null>(null)
const phase = ref<Phase>('starting')
const message = ref('')
const failTitle = ref('Not completed')
let pollTimer: ReturnType<typeof setInterval> | undefined
let closeTimer: ReturnType<typeof setTimeout> | undefined

const community = computed(() =>
  state.value.purpose?.kind === 'age' ? findCommunity(state.value.purpose.community) : undefined,
)
const ageText = computed(() => {
  const g = community.value?.gate
  if (!g) return ''
  if (g.minAge != null && g.maxAge != null) return `ages ${g.minAge} to ${g.maxAge}`
  if (g.minAge != null) return `ages ${g.minAge} and older`
  return `ages under ${g.maxAge! + 1}`
})
const title = computed(() => (state.value.purpose?.kind === 'age' ? 'Verify your age' : `Log in to ${siteName}`))
const subtitle = computed(() =>
  community.value ? `${COMMUNITY_PREFIX}${community.value.slug} is for ${ageText.value}.` : `${siteName} gets a pseudonym, not your name.`,
)

const FAILURES: Record<string, string> = {
  denied: `Nothing was shared with ${siteName}.`,
  invalid_request: `Nothing was shared with ${siteName}.`,
  invalid: 'The proof could not be verified.',
  unavailable: 'The verification service is not available.',
  expired: 'The request expired.',
  banned: `This wallet already has a ${siteName} account, and it is banned.`,
  mismatch: 'This proof belongs to a different account.',
}

function stop() {
  clearInterval(pollTimer)
  clearTimeout(closeTimer)
}

function failWith(kind: string) {
  stop()
  phase.value = 'failed'
  failTitle.value = kind === 'banned' ? 'Account banned' : 'Not completed'
  message.value = FAILURES[kind] ?? 'Something went wrong.'
}

async function start() {
  stop()
  const p = state.value.purpose
  if (!p) return
  phase.value = 'starting'
  sessionId.value = null
  authUrl.value = null
  try {
    const res = await $fetch<{ id: string; authorizationUrl: string }>('/api/vp/session', {
      method: 'POST',
      body: p.kind === 'signin' ? { purpose: 'signin' } : { purpose: 'age', community: p.community },
    })
    sessionId.value = res.id
    authUrl.value = res.authorizationUrl
    phase.value = 'waiting'
    pollTimer = setInterval(poll, 400)
  } catch {
    failWith('unavailable')
  }
}

let polling = false
async function poll() {
  if (!sessionId.value || polling) return
  polling = true
  try {
    const s = await $fetch<{ status: string; failure?: string }>(`/api/vp/session/${sessionId.value}`)
    if (s.status === 'scanned' && phase.value === 'waiting') phase.value = 'scanned'
    else if (s.status === 'responded') phase.value = 'verifying'
    else if (s.status === 'failed') failWith(s.failure ?? 'invalid')
    else if (s.status === 'verified') await complete()
  } finally {
    polling = false
  }
}

async function complete() {
  stop()
  phase.value = 'verifying'
  const c = await $fetch<Completion>(`/api/vp/session/${sessionId.value}/complete`, { method: 'POST' })
  if (!c.ok) return failWith(c.kind)
  await refresh()
  message.value = c.kind === 'created' ? `Account created: u/${c.handle}` : c.kind === 'logged_in' ? `Logged in as u/${c.handle}` : 'Age confirmed'
  phase.value = 'success'
  closeTimer = setTimeout(close, 1800)
}

watch(
  () => state.value.open,
  (open) => {
    if (open) start()
    else {
      stop()
      sessionId.value = null
    }
  },
)

function onKey(e: KeyboardEvent) {
  if (e.key === 'Escape' && state.value.open) close()
}
onMounted(() => window.addEventListener('keydown', onKey))
onBeforeUnmount(() => {
  window.removeEventListener('keydown', onKey)
  stop()
})
</script>

<template>
  <Teleport to="body">
    <Transition
      enter-active-class="transition duration-150"
      enter-from-class="opacity-0"
      leave-active-class="transition duration-150"
      leave-to-class="opacity-0"
    >
      <div v-if="state.open" class="fixed inset-0 z-50 flex items-center justify-center bg-black/45 p-4" @click.self="close">
        <div class="card flex w-full max-w-[880px] overflow-hidden shadow-2xl" role="dialog" aria-modal="true" :aria-label="title">
          <!-- website side -->
          <section class="flex min-w-0 flex-1 flex-col p-8">
            <div class="flex items-start justify-between gap-4">
              <div>
                <h2 class="text-xl font-semibold">{{ title }}</h2>
                <p class="mt-1 text-sm text-muted">{{ subtitle }}</p>
              </div>
              <button class="-mt-1 -mr-2 rounded-full p-1.5 text-muted hover:bg-canvas" aria-label="Close" @click="close">
                <AppIcon name="close" class="size-5" />
              </button>
            </div>

            <div class="flex flex-1 flex-col items-center justify-center py-6">
              <div class="relative size-60 rounded-2xl border border-line bg-white p-4">
                <QrCode
                  v-if="authUrl"
                  :value="authUrl"
                  class="transition-opacity duration-300"
                  :class="phase === 'waiting' ? 'opacity-100' : 'opacity-10'"
                />
                <div
                  v-if="phase !== 'waiting'"
                  class="absolute inset-0 flex flex-col items-center justify-center rounded-2xl bg-white/80 px-6 text-center"
                >
                  <template v-if="phase === 'starting'">
                    <span class="size-10 animate-spin rounded-full border-4 border-brand-soft border-t-brand" />
                  </template>
                  <template v-else-if="phase === 'scanned'">
                    <AppIcon name="phone" class="size-10 text-brand" />
                    <p class="mt-3 font-semibold">Continue on your phone</p>
                  </template>
                  <template v-else-if="phase === 'verifying'">
                    <span class="size-10 animate-spin rounded-full border-4 border-brand-soft border-t-brand" />
                    <p class="mt-3 font-semibold">Checking proof</p>
                  </template>
                  <template v-else-if="phase === 'success'">
                    <span class="flex size-12 items-center justify-center rounded-full bg-brand text-white">
                      <AppIcon name="check" class="size-7" />
                    </span>
                    <p class="mt-3 font-semibold">{{ message }}</p>
                  </template>
                  <template v-else>
                    <span class="flex size-12 items-center justify-center rounded-full bg-adult/10 text-adult">
                      <AppIcon name="ban" class="size-7" />
                    </span>
                    <p class="mt-3 font-semibold">{{ failTitle }}</p>
                    <p class="mt-1 text-sm text-muted">{{ message }}</p>
                  </template>
                </div>
              </div>

              <div class="mt-6 flex h-24 items-start">
                <div v-if="phase === 'failed'" class="flex gap-2">
                  <button class="btn-primary" @click="start">Try again</button>
                  <button class="btn-outline" @click="close">Close</button>
                </div>
                <ol v-else class="space-y-2 text-sm text-muted">
                  <li class="flex gap-3"><span class="font-semibold text-ink">1</span>Open the EUDI Wallet App on your phone</li>
                  <li class="flex gap-3"><span class="font-semibold text-ink">2</span>Tap Scan QR code and scan this code</li>
                  <li class="flex gap-3"><span class="font-semibold text-ink">3</span>Check the request and enter your PIN</li>
                </ol>
              </div>
            </div>
          </section>

          <!-- the person's phone -->
          <section class="hidden items-center justify-center border-l border-line bg-canvas px-10 py-8 md:flex">
            <WalletApp :key="sessionId ?? 'none'" :url="authUrl" />
          </section>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
