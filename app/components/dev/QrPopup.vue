<script setup lang="ts">
// The QR code of this view's request, as an in-page popup. It holds the real request: a phone with
// a wallet that runs zkp_req and the Response Mode it asks for (direct_post.cwt or direct_post.jwt,
// /tech's switch) can scan it, when it can reach this site.
// Simulate scan opens the list of demo phones beside it: pick one, then Scan, and that phone scans
// the code; the popup then stays until Close on the phone's success screen, or Close here.
// Before the scan, a click outside, Esc or Cancel request cancels the request. Once the code has
// been scanned the request is with the wallet, so closing only hides the popup.
import { PROOF_SYSTEMS } from '#shared/registry/circuits'
import { DEV_NAMES, purposeText } from '~/dev/flow'
import { PHONES, ageOn, loadCredentials, type CredentialView, type PhoneDef } from '~/wallet/holder'

const open = defineModel<boolean>('open', { default: false })
const host = useRuntimeConfig().public.siteHost as string
const flow = useDevFlow()
const { state } = flow
const { id: phoneId, phone } = usePhone()
const today = useToday()

const session = computed(() => state.value.session)
const scanned = computed(() => !!session.value && session.value.status !== 'waiting')
/** The page's clock, for the timer. */
const now = ref(Date.now())
let tick: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  tick = setInterval(() => (now.value = Date.now()), 500)
  window.addEventListener('keydown', onKey)
})
onBeforeUnmount(() => {
  clearInterval(tick)
  window.removeEventListener('keydown', onKey)
})
const mmss = computed(() => {
  const s = Math.max(0, Math.round(((session.value?.expiresAt ?? 0) - now.value) / 1000))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
})

function onKey(e: KeyboardEvent) {
  if (open.value && e.key === 'Escape') dismiss()
}

function cancel() {
  open.value = false
  flow.cancel()
}

function dismiss() {
  if (scanned.value) close()
  else cancel()
}

function close() {
  open.value = false
  state.value.phoneShown = false
}

/** The phone picked in the list, and whether it is scanning (Scan). A new request or a closed
 *  popup starts from the list again. */
const picked = ref<PhoneDef['id']>(phoneId.value)
const scanning = ref(false)
// Two sources, compared one by one: the session object itself is new at every poll.
watch(
  [() => session.value?.id, () => state.value.phoneShown],
  () => {
    scanning.value = false
    picked.value = phoneId.value
  },
)

/** Each phone's credential (its encoding and the owner's age), and whether the site accepts a
 *  proof system for that encoding now (/tech). The age range asked for is not checked here: the
 *  wallet decides that. */
const credentials = ref<CredentialView[]>([])
onMounted(async () => {
  try {
    credentials.value = await loadCredentials()
  } catch {
    /* the list goes without the details */
  }
})
const phones = computed(() =>
  PHONES.map((p) => {
    const c = credentials.value.find((x) => p.credentials.includes(x.index))
    const systems = PROOF_SYSTEMS.filter((s) => s.source_format === c?.format && state.value.accepted.includes(s.id)).map((s) => DEV_NAMES[s.id] ?? s.label)
    return { ...p, format: c?.format, age: c ? ageOn(c.attributes.birth_date, today.value) : undefined, systems }
  }),
)
/** The phones by their credential's encoding: the circuits' mdoc phones, then the BBS phone. */
const GROUPS = [
  { format: 'mso_mdoc', title: 'Circuits', detail: 'mso_mdoc: VegaMC, Longfellow' },
  { format: 'bbs_cd', title: 'BBS', detail: 'bbs_cd: committed disclosures' },
] as const
const groups = computed(() => GROUPS.map((g) => ({ ...g, phones: phones.value.filter((p) => (p.format ?? 'mso_mdoc') === g.format) })).filter((g) => g.phones.length))

/** Scan with the picked phone; the site records the phone for the trace when it changed. */
function scan() {
  if (scanned.value) return
  const changed = picked.value !== phoneId.value
  phoneId.value = picked.value
  scanning.value = true
  const id = session.value?.id
  if (id && changed) {
    $fetch(`/api/vp/session/${id}/phone`, { method: 'POST', body: { phone: phone.value.label } }).catch(() => {
      /* the trace misses the change */
    })
  }
}
</script>

<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="open && session" class="vd backdrop" @mousedown.self="dismiss">
        <div :class="['win', { wide: state.phoneShown }]" role="dialog" aria-modal="true" aria-label="Scan QR code">
          <div class="code">
            <p class="section-label">{{ purposeText(session.purpose) }} · {{ host }}</p>
            <h3>{{ scanned ? 'Scanned' : 'Scan with the SIROS ID wallet' }}</h3>
            <div :class="['qr', { scanned }]">
              <QrCode :value="session.authorizationUrl" />
            </div>
            <div class="row">
              <template v-if="!scanned">
                <span class="timer mono">{{ mmss }}</span>
                <a class="link" :href="session.authorizationUrl">Open wallet on this device</a>
                <button v-if="!state.phoneShown" type="button" class="link" @click="flow.simulateScan()">Simulate scan</button>
              </template>
              <span v-else class="timer">Continue on the phone</span>
            </div>
            <button v-if="!scanned" type="button" class="cancel" @click="cancel">Cancel request</button>
            <button v-else type="button" class="cancel" @click="close">Close</button>
          </div>

          <div v-if="state.phoneShown && !scanning" class="phone pick">
            <p class="section-label">Choose a phone</p>
            <div class="phones" role="radiogroup" aria-label="Phone">
              <div v-for="g in groups" :key="g.format" :class="['group', g.format]">
                <p class="group-head"><span class="group-title">{{ g.title }}</span><span class="mono">{{ g.detail }}</span></p>
                <button
                  v-for="p in g.phones"
                  :key="p.id"
                  type="button"
                  role="radio"
                  :aria-checked="picked === p.id"
                  :class="['ph', { on: picked === p.id, off: !p.systems.length }]"
                  @click="picked = p.id"
                >
                  <span class="dot" :style="{ backgroundColor: p.tone }" aria-hidden="true" />
                  <span class="txt">
                    <span class="name">{{ p.label }}<template v-if="p.age != null"> · {{ p.age }}</template></span>
                    <span class="detail mono">{{ p.systems.length ? `accepted: ${p.systems.join(', ')}` : 'not accepted now' }}</span>
                  </span>
                </button>
              </div>
            </div>
            <button type="button" class="go" @click="scan">Scan</button>
          </div>

          <div v-else-if="state.phoneShown" class="phone">
            <div class="phone-bar">
              <p class="phone-label" data-phone-label>
                <span class="dot" :style="{ backgroundColor: phone.tone }" aria-hidden="true" />
                {{ phone.label }}
              </p>
              <button
                type="button"
                class="swap"
                :disabled="scanned"
                :title="scanned ? 'The phone on screen has already scanned the code' : 'Pick another phone'"
                @click="scanning = false"
              >
                Change phone
              </button>
            </div>
            <WalletApp :key="`${session.id}-${phone.id}`" :url="session.authorizationUrl" :phone="phone" auto-scan @finished="close" />
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.backdrop {
  position: fixed;
  inset: 0;
  z-index: 90;
  background: rgba(17, 17, 17, 0.28);
  display: grid;
  place-items: center;
  padding: 24px;
  overflow: auto;
}
.win {
  width: min(420px, 100%);
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 14px;
  box-shadow: 0 30px 80px -20px rgba(0, 0, 0, 0.35);
  display: flex;
}
.win.wide { width: auto; max-width: 100%; }
.code {
  width: min(420px, 100%);
  padding: 24px 28px 22px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  gap: 10px;
}
.section-label { margin: 0; }
h3 { margin: 0 0 6px; font-size: 20px; font-weight: 600; letter-spacing: -0.01em; }
.qr { width: min(320px, 72vw); transition: opacity 0.3s, filter 0.3s; }
.qr.scanned { opacity: 0.12; filter: blur(2px); }
.row { display: flex; gap: 16px; align-items: center; justify-content: center; flex-wrap: wrap; margin-top: 6px; min-height: 22px; }
.timer { font-size: 12.5px; color: var(--muted); }
.link { background: none; border: 0; padding: 0; font-size: 13px; color: var(--ink); text-decoration: underline; text-underline-offset: 3px; text-decoration-color: var(--faint); }
.link:hover { text-decoration-color: var(--ink); }
.cancel { margin-top: 6px; font-size: 12.5px; background: none; border: 0; color: var(--muted); }
.cancel:hover { color: var(--bad); }
.phone { display: flex; flex-direction: column; align-items: center; gap: 12px; padding: 20px 32px; border-left: 1px solid var(--line); background: var(--surface); border-radius: 0 14px 14px 0; }
.phone-bar { display: flex; width: 330px; align-items: center; justify-content: space-between; }
.phone-label { display: flex; align-items: center; gap: 8px; margin: 0; font-size: 13.5px; font-weight: 600; }
.dot { width: 10px; height: 10px; border-radius: 999px; }
.swap { font-size: 12px; font-weight: 600; padding: 4px 12px; border: 1px solid var(--line); border-radius: 999px; background: var(--bg); }
.swap:hover:not(:disabled) { border-color: var(--faint); }
.swap:disabled { opacity: 0.4; cursor: not-allowed; }
.pick { width: 394px; justify-content: center; gap: 14px; }
.pick .section-label { align-self: flex-start; }
.phones { display: flex; flex-direction: column; gap: 12px; width: 100%; }
.group { display: flex; flex-direction: column; gap: 6px; padding: 10px; border: 1.5px solid var(--c); border-radius: 11px; background: var(--band); }
.group.mso_mdoc { --c: #1f55c8; --band: #f3f7fe; }
.group.bbs_cd { --c: #2e5e6e; --band: #f1f7f8; }
.group-head { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; margin: 0 2px 2px; font-size: 11px; color: var(--c); }
.group-title { font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; }
.ph { display: flex; align-items: center; gap: 12px; width: 100%; text-align: left; padding: 10px 12px; border: 1px solid var(--line); border-radius: 9px; background: var(--bg); }
.ph:hover { border-color: var(--faint); }
.ph.on { border-color: var(--sel); box-shadow: 0 0 0 1px var(--sel); }
.ph.off .detail { color: var(--bad); }
.ph .txt { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.ph .name { font-size: 13.5px; font-weight: 600; }
.ph .detail { font-size: 11px; color: var(--muted); }
.go { align-self: stretch; font-size: 14px; font-weight: 500; padding: 10px 12px; border-radius: 8px; border: 1px solid var(--sel); background: var(--sel); color: #fff; }
.go:hover { background: var(--sel-hover); border-color: var(--sel-hover); }
.fade-enter-active, .fade-leave-active { transition: opacity 0.15s; }
.fade-enter-from, .fade-leave-to { opacity: 0; }
@media (max-width: 860px) {
  .win.wide { flex-direction: column; }
  .phone { border-left: 0; border-top: 1px solid var(--line); border-radius: 0 0 14px 14px; }
}
</style>
