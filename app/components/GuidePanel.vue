<script setup lang="ts">
import { findCommunity } from '#shared/data/communities'
import type { CredentialView } from '~/wallet/holder'
import { loadCredentials } from '~/wallet/holder'
import type { GuideStep } from '~/guide/steps'
import { STAGES, guideStep } from '~/guide/steps'

// The presenter's guide, docked beside the product. It is not part of Community or the wallet: it
// follows the flow state and says, for the current step, what the step is about
// (app/guide/steps.ts).
const guide = useGuidePanel()
const route = useRoute()
const { account, bannedHandle, memberships } = useAccount()
const wallet = useWallet()
const walletFlow = useWalletFlow()
const dialogFlow = useDialogFlow()
const last = useLastOutcome()
const today = useToday()
const config = useRuntimeConfig().public
const community = computed(() => (route.params.slug ? findCommunity(String(route.params.slug)) : undefined))
const { access } = useCommunityAccess(community)
const credentials = ref<CredentialView[]>([])

onMounted(async () => {
  guide.restore()
  try {
    credentials.value = await loadCredentials()
  } catch {
    /* the credential's details stay out of the guide */
  }
})
// An outcome describes the page it happened on; a new page starts afresh.
watch(
  () => route.fullPath,
  () => (last.value = null),
)

const step = computed(() =>
  guideStep({
    siteName: String(config.siteName),
    siteHost: String(config.siteHost),
    today: today.value,
    dialog: { ...dialogFlow.value, open: wallet.state.value.open, purpose: wallet.state.value.purpose },
    wallet: walletFlow.value,
    last: last.value,
    page: community.value ? { kind: 'community', community: community.value } : route.path === '/' ? { kind: 'home' } : { kind: 'other' },
    access: community.value ? access.value : null,
    account: account.value,
    bannedHandle: bannedHandle.value,
    membership: community.value?.nymHost ? (memberships.value[community.value.slug] ?? null) : null,
    credentials: credentials.value,
  }),
)

// History of the steps shown so far, so the presenter can go back to one that passed quickly.
// Each new step (any interaction: on the phone, the site or the dialog) jumps back to the present.
// A step that changes without becoming a new one (details filled in) updates its history entry.
const MAX_HISTORY = 50
const history = ref<Array<{ key: number; step: GuideStep }>>([])
const viewing = ref<number | null>(null)
let nextKey = 0
watch(
  step,
  (s) => {
    const snap = JSON.parse(JSON.stringify(s)) as GuideStep
    const last = history.value.at(-1)
    if (last && last.step.id === s.id && last.step.context === s.context) {
      last.step = snap
      return
    }
    history.value.push({ key: nextKey++, step: snap })
    if (history.value.length > MAX_HISTORY) history.value.shift()
    viewing.value = null
  },
  { immediate: true },
)
const position = computed(() => viewing.value ?? history.value.length - 1)
const shown = computed(() => (viewing.value == null ? step.value : history.value[viewing.value]!.step))
const shownKey = computed(() => history.value[position.value]?.key ?? 0)
function back() {
  if (position.value > 0) viewing.value = position.value - 1
}
function forward() {
  if (viewing.value == null) return
  viewing.value = viewing.value + 1 >= history.value.length - 1 ? null : viewing.value + 1
}

const detailsOpen = ref(false)
watch(shownKey, () => (detailsOpen.value = false))
</script>

<template>
  <aside
    class="guide fixed inset-y-0 right-0 z-[60] flex flex-col border-l border-black bg-[#15171a] text-[#c9ced6]"
    :style="{ width: guide.width.value }"
    aria-label="Guide"
    :data-guide-step="step.id"
  >
    <template v-if="guide.open.value">
      <header class="flex h-14 shrink-0 items-center gap-2.5 border-b border-white/10 px-5">
        <svg viewBox="0 0 24 24" class="size-[18px] text-[#8b939e]" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M2 4h6a4 4 0 0 1 4 4v12a3 3 0 0 0-3-3H2zM22 4h-6a4 4 0 0 0-4 4v12a3 3 0 0 1 3-3h7z" />
        </svg>
        <span class="text-sm font-semibold text-white">Guide</span>
        <div class="ml-auto flex items-center gap-1">
          <button
            class="rounded-md p-1.5 text-[#8b939e] hover:bg-white/10 hover:text-white disabled:pointer-events-none disabled:opacity-30"
            aria-label="Previous step"
            title="Previous step"
            :disabled="position === 0"
            @click="back"
          >
            <svg viewBox="0 0 24 24" class="size-[18px]" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 6l-6 6 6 6" /></svg>
          </button>
          <span class="min-w-[3.25rem] text-center text-xs tabular-nums text-[#8b939e]">{{ position + 1 }} / {{ history.length }}</span>
          <button
            class="rounded-md p-1.5 text-[#8b939e] hover:bg-white/10 hover:text-white disabled:pointer-events-none disabled:opacity-30"
            aria-label="Next step"
            title="Next step"
            :disabled="viewing == null"
            @click="forward"
          >
            <svg viewBox="0 0 24 24" class="size-[18px]" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 6l6 6-6 6" /></svg>
          </button>
        </div>
        <button class="ml-2 rounded-md p-1.5 text-[#8b939e] hover:bg-white/10 hover:text-white" aria-label="Hide guide" title="Hide guide" @click="guide.toggle">
          <svg viewBox="0 0 24 24" class="size-[18px]" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <rect x="3" y="3" width="18" height="18" rx="2" /><path d="M15 3v18M8 9l3 3-3 3" />
          </svg>
        </button>
      </header>

      <div class="relative min-h-0 flex-1">
        <div class="h-full overflow-y-auto px-5 pt-5 pb-10">
          <div v-if="viewing != null" class="mb-4 flex items-center justify-between rounded-md bg-white/8 px-3 py-2 text-xs">
            <span class="text-[#8b939e]">Earlier step</span>
            <button class="font-semibold text-white hover:underline" @click="viewing = null">Back to current</button>
          </div>
          <Transition
            mode="out-in"
            enter-active-class="transition duration-200 ease-out"
            enter-from-class="opacity-0 translate-y-1"
            leave-active-class="transition duration-100 ease-in"
            leave-to-class="opacity-0"
          >
            <div :key="shownKey">
              <p class="font-mono text-[11px] tracking-[0.06em] text-[#8b939e] uppercase">{{ shown.context }}</p>

              <ol v-if="shown.stage != null" class="mt-3 grid grid-cols-6 gap-1" aria-label="Request progress">
                <li v-for="(s, k) in STAGES" :key="s" :aria-current="k === shown.stage ? 'step' : undefined">
                  <span class="block h-1 rounded-full" :class="k < shown.stage ? 'bg-[#6b7480]' : k === shown.stage ? 'bg-white' : 'bg-white/12'" />
                  <span class="mt-1.5 block text-[10.5px] leading-tight" :class="k === shown.stage ? 'font-semibold text-white' : 'text-[#6b7480]'">{{ s }}</span>
                </li>
              </ol>

              <h2 class="mt-4 text-[22px] leading-tight font-semibold text-white">{{ shown.title }}</h2>
              <p class="mt-3 text-[15px] leading-relaxed">{{ shown.summary }}</p>

              <details
                v-if="shown.details.length"
                class="group mt-6 border-t border-white/10 pt-4"
                :open="detailsOpen"
                @toggle="detailsOpen = ($event.target as HTMLDetailsElement).open"
              >
                <summary class="flex cursor-pointer list-none items-center gap-1.5 text-[13px] font-semibold text-[#e3e6ea] select-none [&::-webkit-details-marker]:hidden">
                  <svg viewBox="0 0 24 24" class="size-4 transition-transform group-open:rotate-90" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M9 6l6 6-6 6" />
                  </svg>
                  Details
                </summary>
                <div class="mt-4 space-y-5">
                  <section v-for="sec in shown.details" :key="sec.heading">
                    <h3 class="text-[12px] font-semibold text-[#8b939e]">{{ sec.heading }}</h3>
                    <dl v-if="sec.rows?.length && sec.stacked" class="mt-2 space-y-2">
                      <div v-for="r in sec.rows" :key="r.label">
                        <dt class="text-[11.5px] text-[#8b939e]" :class="r.code && 'font-mono'">{{ r.label }}</dt>
                        <dd class="text-[13px] leading-snug break-words text-[#e3e6ea]" :class="r.mono && 'font-mono text-[12px] break-all'">{{ r.value }}</dd>
                      </div>
                    </dl>
                    <dl v-else-if="sec.rows?.length" class="mt-2 grid grid-cols-[minmax(0,8.5rem)_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-[13px] leading-snug">
                      <template v-for="r in sec.rows" :key="r.label">
                        <dt class="text-[#8b939e]">{{ r.label }}</dt>
                        <dd class="break-words text-[#e3e6ea]" :class="r.mono && 'font-mono text-[12px] break-all'">{{ r.value }}</dd>
                      </template>
                    </dl>
                    <ul v-if="sec.items?.length" class="mt-2 space-y-1.5 text-[13px] leading-snug">
                      <li v-for="item in sec.items" :key="item" class="flex gap-2">
                        <span class="text-[#6b7480]" aria-hidden="true">–</span>
                        <span>{{ item }}</span>
                      </li>
                    </ul>
                  </section>
                </div>
              </details>
            </div>
          </Transition>
        </div>
        <!-- fades out what continues below the fold -->
        <div class="pointer-events-none absolute inset-x-0 bottom-0 h-10 bg-linear-to-t from-[#15171a] to-transparent" />
      </div>

      <footer class="flex shrink-0 gap-5 border-t border-white/10 px-5 py-3 text-xs">
        <a href="/tech" target="community-tech" class="text-[#8b939e] hover:text-white">Technical view ↗</a>
        <a href="/mod" target="community-mod" class="text-[#8b939e] hover:text-white">Moderation ↗</a>
      </footer>
    </template>

    <button v-else class="flex h-full w-full flex-col items-center gap-3 pt-4 text-[#8b939e] hover:text-white" aria-label="Show guide" title="Show guide" @click="guide.toggle">
      <svg viewBox="0 0 24 24" class="size-[18px]" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <rect x="3" y="3" width="18" height="18" rx="2" /><path d="M15 3v18M11 9l-3 3 3 3" />
      </svg>
      <span class="rotate-180 text-xs font-semibold tracking-wide [writing-mode:vertical-rl]">Guide</span>
    </button>
  </aside>
</template>
