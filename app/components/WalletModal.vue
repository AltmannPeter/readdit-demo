<script setup lang="ts">
import { findCommunity, COMMUNITY_PREFIX } from '#shared/data/communities'
import type { DialogPhase, VerificationMetrics } from '~/composables/useFlow'
import type { WalletPurpose } from '~/composables/useWallet'
import { ageOn, loadCredentials } from '~/wallet/holder'

// Site side of the cross-device flow. The server owns the OpenID4VP session and runs
// the verifier; this dialog shows the QR code, follows the status and applies the result
// to this browser's login. It publishes its state for the guide panel (useDialogFlow).
// Closing it before the request ends cancels the session on the server.
// The phone beside it is one of the demo's phones; Swap phone hands over to the next one while
// the QR code is on screen (the site records the swap for the technical view).

interface Completion {
  ok: boolean
  kind: string
  handle?: string
  /** The age proof was recorded too (a sign-in at an age-restricted community). */
  age?: boolean
  /** A community account: its community, and whether it was just linked to the Community account. */
  community?: string
  linked?: boolean
}

const { state, close } = useWallet()
const { refresh, account } = useAccount()
const { phone, other: nextPhone, swap: swapPhone } = usePhone()
const today = useToday()
/** Each phone's owner's age today, from the birth date in the phone's credential. */
const ages = ref<Record<string, number>>({})
onMounted(async () => {
  try {
    const creds = await loadCredentials()
    for (const c of creds) ages.value[String(c.index)] = ageOn(c.attributes.birth_date, today.value)
  } catch {
    /* the label goes without the age */
  }
})
/** The phone was swapped during this request. */
const swapped = ref(false)
/** A swap is animating (a new request replaces the phone without animation). */
const swapAnimating = ref(false)
let swapTimer: ReturnType<typeof setTimeout> | undefined
const phoneAge = computed(() => ages.value[String(phone.value.credentials[0])])
/** Swapping makes sense until the phone on screen has scanned the code. */
const canSwap = computed(() => phase.value !== 'scanned' && phase.value !== 'verifying')
function swap() {
  if (!canSwap.value) return
  swapAnimating.value = true
  clearTimeout(swapTimer)
  swapTimer = setTimeout(() => (swapAnimating.value = false), 600)
  swapPhone()
  if (sessionId.value) swapped.value = true
  if (sessionId.value && (phase.value === 'waiting' || phase.value === 'starting')) {
    $fetch(`/api/vp/session/${sessionId.value}/phone`, { method: 'POST', body: { phone: phone.value.label } }).catch(() => {
      /* the technical view misses the swap */
    })
  }
}
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
/** The request this dialog runs; a newer start or a close makes older answers stale. */
let run = 0
let activePurpose: WalletPurpose | null = null
let pollErrors = 0

const dialogFlow = useDialogFlow()
const lastOutcome = useLastOutcome()
watchEffect(() => {
  dialogFlow.value = { phase: phase.value, authUrl: authUrl.value, failure: failure.value, completion: completion.value, verification: verification.value, swapped: swapped.value }
})

const community = computed(() => {
  const p = state.value.purpose
  const slug = p?.kind === 'age' || p?.kind === 'community' ? p.community : p?.kind === 'signin' ? p.community : undefined
  return slug ? findCommunity(slug) : undefined
})
const communityName = computed(() => (community.value ? `${COMMUNITY_PREFIX}${community.value.slug}` : ''))
const ageText = computed(() => {
  const g = community.value?.gate
  if (!g) return ''
  if (g.minAge != null && g.maxAge != null) return `ages ${g.minAge} to ${g.maxAge}`
  if (g.minAge != null) return `ages ${g.minAge} and older`
  return `ages under ${g.maxAge! + 1}`
})
const title = computed(() => {
  const p = state.value.purpose
  if (p?.kind === 'community') return `Join ${communityName.value}`
  if (p?.kind === 'age' || community.value) return 'Verify your age'
  return p?.intent === 'signup' ? `Sign up for ${siteName}` : `Log in to ${siteName}`
})
const subtitle = computed(() => {
  if (!community.value) return ''
  const p = state.value.purpose
  if (p?.kind === 'community') {
    return `${communityName.value} is fully anonymous. Your pseudonym will be unique to /${community.value.slug}. One account per person.${p.link && account.value ? ` You chose to link it to u/${account.value.handle}.` : ''}`
  }
  const gated = `${COMMUNITY_PREFIX}${community.value.slug} is for ${ageText.value}.`
  return state.value.purpose?.kind === 'signin' ? `${gated} The same step logs you in with a pseudonym.` : gated
})

const FAILURES: Record<string, string> = {
  denied: `Nothing was shared with ${siteName}.`,
  invalid_request: `Nothing was shared with ${siteName}.`,
  invalid: `${siteName} could not verify the response.`,
  unavailable: 'Verification is not available right now. Try again later.',
  none_accepted: `${siteName} does not accept any proof yet. Switch one on in the technical view, then try again.`,
  expired: 'The code has expired. Try again.',
  cancelled: 'The request was cancelled. Try again.',
  gone: 'This code is no longer valid. Try again.',
  banned: `This wallet's ${siteName} account has been banned.`,
  community_banned: 'This wallet\'s account in this community has been banned.',
  other_pseudonym: 'Your Community account is linked to another account in this community, from another wallet. Nothing was changed.',
  linked_elsewhere: 'This account in the community is linked to another Community account. Nothing was changed.',
  mismatch: 'The pseudonym in this proof does not match your account. The age proof was not applied.',
  no_account: `There is no ${siteName} account for this wallet. Sign up to create one.`,
  account_exists: 'There is already an account associated with this user. Log in instead.',
  logged_out: 'You are no longer logged in. Log in and try again.',
  login_required: 'Log in to verify your age.',
  age_refused: 'Your verified age does not meet this requirement.',
  age_verified: 'Your age is already verified for this community.',
}
const TITLES: Record<string, string> = {
  none_accepted: 'No proof accepted',
  community_banned: 'Account banned',
  other_pseudonym: 'Pseudonym does not match',
  linked_elsewhere: 'Linked to another account',
  mismatch: 'Pseudonym does not match', banned: 'Account banned', no_account: 'No account', account_exists: 'Account already exists' }
/** Failures that a new request would not change. */
const FINAL = new Set(['other_pseudonym', 'linked_elsewhere', 'community_banned', 'no_account', 'account_exists', 'logged_out', 'login_required', 'age_refused', 'age_verified'])
const retryable = computed(() => !failure.value || !FINAL.has(failure.value))

/** The refusal code in an error body (`data.error`), and the HTTP status. */
function errorOf(e: unknown): { status?: number; code?: string } {
  const err = e as { statusCode?: number; data?: { data?: { error?: string } } }
  return { status: err.statusCode, code: err.data?.data?.error }
}

function stop() {
  clearInterval(pollTimer)
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
  phoneFinished = false
  swapped.value = false
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
          ? { purpose: 'signin', intent: p.intent, ...(p.community && { community: p.community }), origin: window.location.origin, phone: phone.value.label }
          : { purpose: p.kind, community: p.community, ...(p.kind === 'community' && { link: p.link }), origin: window.location.origin, phone: phone.value.label },
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
    return failWith(c.kind === 'banned' && c.community ? 'community_banned' : c.kind)
  }
  await refresh()
  completion.value = c
  const account = c.kind === 'created' ? `Account created: u/${c.handle}` : c.kind === 'logged_in' ? `Logged in as u/${c.handle}` : ''
  if (c.community) {
    message.value = c.kind === 'created' ? `Joined ${COMMUNITY_PREFIX}${c.community} as u/${c.handle}` : `In ${COMMUNITY_PREFIX}${c.community} as u/${c.handle}`
    note.value = c.linked ? 'Linked to your Community account.' : ''
  } else if (c.age) {
    message.value = 'Age verified'
    note.value = account
  } else {
    message.value = account || 'Age verified'
    note.value = c.kind === 'logged_in' && activePurpose?.kind === 'signin' && activePurpose.intent === 'signup' ? 'This wallet already has an account.' : ''
  }
  phase.value = 'success'
  if (activePurpose) lastOutcome.value = { purpose: activePurpose, ok: true, kind: c.kind, handle: c.handle }
  // The dialog stays open until Close on the phone's success screen (or the site's own close).
  if (phoneFinished) close()
}

/** Close on the phone's success screen: back to the site once the site has applied the result. */
let phoneFinished = false
function onPhoneFinished() {
  phoneFinished = true
  if (phase.value === 'success') close()
}

/** "Sign up" after a log-in found no account: a new request, applied as a sign-up. */
function signUpInstead() {
  state.value = { open: true, purpose: { kind: 'signin', intent: 'signup' } }
  start()
}
function logInInstead() {
  state.value = { open: true, purpose: { kind: 'signin', intent: 'login' } }
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
                <p v-if="subtitle" class="mt-1 text-sm text-muted">{{ subtitle }}</p>
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
                  <button v-else-if="failure === 'account_exists'" class="btn-primary" @click="logInInstead">Log in</button>
                  <button v-else-if="retryable" class="btn-primary" @click="start">Try again</button>
                  <button class="btn-outline" @click="close">Close</button>
                </div>
                <ol v-else class="space-y-2 text-sm text-muted">
                  <li class="flex gap-3"><span class="font-semibold text-ink">1</span>Open an EUDI Wallet App on your phone</li>
                  <li class="flex gap-3"><span class="font-semibold text-ink">2</span>Tap the scan button and point your phone at this code</li>
                  <li class="flex gap-3"><span class="font-semibold text-ink">3</span>Review the request and enter any 6-digit PIN</li>
                </ol>
              </div>
            </div>
          </section>

          <!-- the phone in use: one of the demo's phones, swappable while the QR code is on screen -->
          <section class="hidden flex-col items-center justify-center gap-3 border-l border-line bg-canvas px-10 py-5 md:flex">
            <div class="flex w-[330px] items-center justify-between">
              <p class="flex items-center gap-2 text-sm font-semibold" aria-live="polite" data-phone-label>
                <span class="size-2.5 rounded-full" :style="{ backgroundColor: phone.tone }" aria-hidden="true" />
                {{ phone.label }}<span v-if="phoneAge != null" class="font-normal text-muted">· {{ phoneAge }}</span>
              </p>
              <button
                class="flex items-center gap-1.5 rounded-full border border-line bg-surface px-3 py-1 text-xs font-semibold hover:bg-canvas disabled:cursor-not-allowed disabled:opacity-40"
                :disabled="!canSwap"
                :title="canSwap ? `Hand over to the ${nextPhone.label.replace(/^\w/, (c) => c.toLowerCase())}` : 'The phone on screen has already scanned the code'"
                @click="swap"
              >
                <AppIcon name="swap" class="size-3.5" />
                Swap phone
              </button>
            </div>
            <!-- a swap slides the other phone in; a new request replaces the phone at once -->
            <div :key="phone.id" :class="swapAnimating && 'phone-swap-in'">
              <WalletApp :key="`${attempt}-${phone.id}`" :url="authUrl" :phone="phone" @finished="onPhoneFinished" />
            </div>
          </section>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
