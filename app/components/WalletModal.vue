<script setup lang="ts">
import { findCommunity, COMMUNITY_PREFIX } from '#shared/data/communities'
import type { DialogPhase, VerificationMetrics } from '~/composables/useFlow'
import type { WalletPurpose } from '~/composables/useWallet'

// Site side of the cross-device flow. The server owns the OpenID4VP session and runs
// the verifier; this dialog shows the QR code, follows the status and applies the result
// to this browser's login. It publishes its state for the guide panel (useDialogFlow).
// Closing it before the request ends cancels the session on the server.

interface Completion {
  ok: boolean
  kind: string
  handle?: string
  /** The age proof was recorded too (a sign-in at an age-restricted community). */
  age?: boolean
}

const { state, close } = useWallet()
const { refresh } = useAccount()
const guide = useGuidePanel()
const siteName = useRuntimeConfig().public.siteName as string

const sessionId = ref<string | null>(null)
const authUrl = ref<string | null>(null)
const phase = ref<DialogPhase>('starting')
const failure = ref<string | null>(null)
const completion = ref<Completion | null>(null)
const verification = ref<VerificationMetrics | null>(null)
const message = ref('')
const note = ref('')
const failTitle = ref('Not completed')
/** One phone per attempt: the wallet starts on its home screen for every new request. */
const attempt = ref(0)
let pollTimer: ReturnType<typeof setInterval> | undefined
let closeTimer: ReturnType<typeof setTimeout> | undefined
/** The request this dialog runs; a newer start or a close makes older answers stale. */
let run = 0
let activePurpose: WalletPurpose | null = null
let pollErrors = 0

const dialogFlow = useDialogFlow()
const lastOutcome = useLastOutcome()
watchEffect(() => {
  dialogFlow.value = { phase: phase.value, authUrl: authUrl.value, failure: failure.value, completion: completion.value, verification: verification.value }
})

const community = computed(() => {
  const p = state.value.purpose
  const slug = p?.kind === 'age' ? p.community : p?.kind === 'signin' ? p.community : undefined
  return slug ? findCommunity(slug) : undefined
})
const ageText = computed(() => {
  const g = community.value?.gate
  if (!g) return ''
  if (g.minAge != null && g.maxAge != null) return `ages ${g.minAge} to ${g.maxAge}`
  if (g.minAge != null) return `ages ${g.minAge} and older`
  return `ages under ${g.maxAge! + 1}`
})
const title = computed(() => {
  const p = state.value.purpose
  if (p?.kind === 'age' || community.value) return 'Verify your age'
  return p?.intent === 'signup' ? `Sign up for ${siteName}` : `Log in to ${siteName}`
})
const subtitle = computed(() => {
  if (!community.value) return `Use the SIROS ID app on your phone. ${siteName} receives a pseudonym, not your name or email address.`
  const gated = `${COMMUNITY_PREFIX}${community.value.slug} is for ${ageText.value}.`
  return state.value.purpose?.kind === 'signin' ? `${gated} The same step logs you in with a pseudonym.` : gated
})

const FAILURES: Record<string, string> = {
  denied: `Nothing was shared with ${siteName}.`,
  invalid_request: `Nothing was shared with ${siteName}.`,
  invalid: `${siteName} could not verify the response.`,
  unavailable: 'Verification is not available right now. Try again later.',
  expired: 'The code has expired. Try again.',
  cancelled: 'The request was cancelled. Try again.',
  gone: 'This code is no longer valid. Try again.',
  banned: `This wallet's ${siteName} account has been banned.`,
  mismatch: 'The response belongs to a different account.',
  no_account: `There is no ${siteName} account for this wallet. Sign up to create one.`,
  logged_out: 'You are no longer logged in. Log in and try again.',
  login_required: 'Log in to verify your age.',
  age_refused: 'Your verified age does not meet this requirement.',
  age_verified: 'Your age is already verified for this community.',
}
const TITLES: Record<string, string> = { banned: 'Account banned', no_account: 'No account' }
/** Failures that a new request would not change. */
const FINAL = new Set(['no_account', 'logged_out', 'login_required', 'age_refused', 'age_verified'])
const retryable = computed(() => !failure.value || !FINAL.has(failure.value))

/** The refusal code in an error body (`data.error`), and the HTTP status. */
function errorOf(e: unknown): { status?: number; code?: string } {
  const err = e as { statusCode?: number; data?: { data?: { error?: string } } }
  return { status: err.statusCode, code: err.data?.data?.error }
}

function stop() {
  clearInterval(pollTimer)
  clearTimeout(closeTimer)
}

function failWith(kind: string) {
  stop()
  phase.value = 'failed'
  failure.value = kind
  failTitle.value = TITLES[kind] ?? 'Not completed'
  message.value = FAILURES[kind] ?? 'Something went wrong.'
  note.value = ''
  if (activePurpose) lastOutcome.value = { purpose: activePurpose, ok: false, kind }
}

async function start() {
  stop()
  const p = state.value.purpose
  if (!p) return
  const mine = ++run
  attempt.value++
  activePurpose = p
  phase.value = 'starting'
  failure.value = null
  completion.value = null
  verification.value = null
  sessionId.value = null
  authUrl.value = null
  note.value = ''
  pollErrors = 0
  let res: { id: string; authorizationUrl: string }
  try {
    res = await $fetch<{ id: string; authorizationUrl: string }>('/api/vp/session', {
      method: 'POST',
      body:
        p.kind === 'signin'
          ? { purpose: 'signin', intent: p.intent, ...(p.community && { community: p.community }) }
          : { purpose: 'age', community: p.community },
    })
  } catch (e) {
    if (mine !== run) return
    const { code } = errorOf(e)
    if (code === 'login_required' || code === 'age_refused' || code === 'age_verified') await refresh()
    return failWith(code && code in FAILURES ? code : 'unavailable')
  }
  if (mine !== run) {
    // Closed or restarted while the session was being created.
    cancel(res.id)
    return
  }
  sessionId.value = res.id
  authUrl.value = res.authorizationUrl
  phase.value = 'waiting'
  pollTimer = setInterval(poll, 400)
}

/** Ends a session on the server that this dialog no longer follows. */
function cancel(id: string) {
  $fetch(`/api/vp/session/${id}/cancel`, { method: 'POST' }).catch(() => {
    /* the session expires on its own */
  })
}

let polling = false
async function poll() {
  const id = sessionId.value
  if (!id || polling) return
  const mine = run
  polling = true
  try {
    const s = await $fetch<{ status: string; failure?: string; verification?: VerificationMetrics }>(`/api/vp/session/${id}`)
    if (mine !== run) return
    pollErrors = 0
    if (s.verification) verification.value = s.verification
    if (s.status === 'scanned' && phase.value === 'waiting') phase.value = 'scanned'
    else if (s.status === 'responded') phase.value = 'verifying'
    else if (s.status === 'failed') failWith(s.failure ?? 'invalid')
    else if (s.status === 'verified') await complete(id, mine)
  } catch (e) {
    if (mine !== run) return
    const { status } = errorOf(e)
    // 404: the server no longer knows the session (the demo was reset); 403: another browser's.
    if (status === 404 || status === 403) failWith('gone')
    else if (++pollErrors >= 10) failWith('unavailable')
  } finally {
    polling = false
  }
}

async function complete(id: string, mine: number) {
  stop()
  phase.value = 'verifying'
  let c: Completion
  try {
    c = await $fetch<Completion>(`/api/vp/session/${id}/complete`, { method: 'POST' })
  } catch (e) {
    if (mine !== run) return
    const { status } = errorOf(e)
    return failWith(status === 404 || status === 403 ? 'gone' : 'unavailable')
  }
  if (mine !== run) return
  if (!c.ok) {
    if (c.kind === 'banned' || c.kind === 'logged_out') await refresh()
    return failWith(c.kind)
  }
  await refresh()
  completion.value = c
  const account = c.kind === 'created' ? `Account created: u/${c.handle}` : c.kind === 'logged_in' ? `Logged in as u/${c.handle}` : ''
  if (c.age) {
    message.value = 'Age verified'
    note.value = account
  } else {
    message.value = account || 'Age verified'
    note.value = c.kind === 'logged_in' && activePurpose?.kind === 'signin' && activePurpose.intent === 'signup' ? 'This wallet already has an account.' : ''
  }
  phase.value = 'success'
  if (activePurpose) lastOutcome.value = { purpose: activePurpose, ok: true, kind: c.kind, handle: c.handle }
  closeTimer = setTimeout(close, 1800)
}

/** "Sign up" after a log-in found no account: a new request, applied as a sign-up. */
function signUpInstead() {
  state.value = { open: true, purpose: { kind: 'signin', intent: 'signup' } }
  start()
}

watch(
  () => state.value.open,
  (open) => {
    if (open) return start()
    stop()
    run++
    // Closed before the request ended: the server cancels the session, and the guide says so.
    if (sessionId.value && phase.value !== 'success' && phase.value !== 'failed') {
      cancel(sessionId.value)
      if (activePurpose) lastOutcome.value = { purpose: activePurpose, ok: false, kind: 'closed' }
    }
    sessionId.value = null
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
      <!-- covers the site, not the guide panel beside it -->
      <div
        v-if="state.open"
        class="fixed inset-y-0 left-0 z-50 flex items-center justify-center bg-black/45 p-4"
        :style="{ right: guide.width.value }"
        @click.self="close"
      >
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
                    <p class="mt-3 font-semibold">Verifying</p>
                  </template>
                  <template v-else-if="phase === 'success'">
                    <span class="flex size-12 items-center justify-center rounded-full bg-brand text-white">
                      <AppIcon name="check" class="size-7" />
                    </span>
                    <p class="mt-3 font-semibold">{{ message }}</p>
                    <p v-if="note" class="mt-1 text-sm text-muted">{{ note }}</p>
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
                  <button v-if="failure === 'no_account'" class="btn-primary" @click="signUpInstead">Sign up</button>
                  <button v-else-if="retryable" class="btn-primary" @click="start">Try again</button>
                  <button class="btn-outline" @click="close">Close</button>
                </div>
                <ol v-else class="space-y-2 text-sm text-muted">
                  <li class="flex gap-3"><span class="font-semibold text-ink">1</span>Open SIROS ID on your phone</li>
                  <li class="flex gap-3"><span class="font-semibold text-ink">2</span>Tap the scan button and point your phone at this code</li>
                  <li class="flex gap-3"><span class="font-semibold text-ink">3</span>Review the request and enter any 6-digit PIN</li>
                </ol>
              </div>
            </div>
          </section>

          <!-- the person's phone -->
          <section class="hidden items-center justify-center border-l border-line bg-canvas px-10 py-8 md:flex">
            <WalletApp :key="attempt" :url="authUrl" />
          </section>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
