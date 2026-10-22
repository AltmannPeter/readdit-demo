<script setup lang="ts">
// The nym_auth attestation in either encoding, with the values of a demo credential: for mso_mdoc
// the phone on screen's mdoc (the teen's when that phone holds the BBS credential), for bbs_cd the
// teen's BBS credential. Closes on a click outside or Esc.
import { attestationFor } from '~/dev/attestation'
import { PHONES, loadCredentials, type CredentialView } from '~/wallet/holder'

const open = defineModel<boolean>('open', { default: false })
const { phone } = usePhone()
const encoding = ref<'mso_mdoc' | 'bbs_cd'>('mso_mdoc')
const credentials = ref<CredentialView[]>([])
const showRaw = ref(false)

const credential = computed(() => {
  const all = credentials.value.filter((c) => c.format === encoding.value)
  return all.find((c) => phone.value.credentials.includes(c.index)) ?? all[0]
})
const owner = computed(() => PHONES.find((p) => credential.value && p.credentials.includes(credential.value.index))?.label)
const view = computed(() => (credential.value ? attestationFor(credential.value) : null))

watch(open, async (o) => {
  if (!o) return
  showRaw.value = false
  try {
    credentials.value = await loadCredentials()
  } catch {
    credentials.value = []
  }
  encoding.value = credentials.value.find((c) => phone.value.credentials.includes(c.index))?.format ?? 'mso_mdoc'
})

function onKey(e: KeyboardEvent) {
  if (open.value && e.key === 'Escape') open.value = false
}
onMounted(() => window.addEventListener('keydown', onKey))
onBeforeUnmount(() => window.removeEventListener('keydown', onKey))
</script>

<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="open && view" class="vd backdrop" @mousedown.self="open = false">
        <div class="win" role="dialog" aria-modal="true" :aria-label="view.title">
          <header>
            <div class="seg" role="radiogroup" aria-label="Encoding">
              <button type="button" role="radio" :aria-checked="encoding === 'mso_mdoc'" :class="{ on: encoding === 'mso_mdoc' }" @click="encoding = 'mso_mdoc'">
                Circuit · mso_mdoc
              </button>
              <button type="button" role="radio" :aria-checked="encoding === 'bbs_cd'" :class="{ on: encoding === 'bbs_cd' }" @click="encoding = 'bbs_cd'">
                BBS · bbs_cd
              </button>
            </div>
            <button type="button" class="close" @click="open = false">Close</button>
          </header>

          <h3>{{ view.title }}</h3>
          <p v-if="owner && credential" class="type">The credential on the {{ owner.replace(/^\w/, (c) => c.toLowerCase()) }}, born {{ credential.attributes.birth_date }}</p>
          <p class="type"><span>{{ view.typeLabel }}</span> <code>{{ view.typeValue }}</code></p>

          <table>
            <thead>
              <tr><th>Attribute</th><th>Type</th><th>{{ encoding === 'bbs_cd' ? 'Messages' : 'Presence' }}</th><th>Example value</th></tr>
            </thead>
            <tbody>
              <tr v-for="r in view.rows" :key="r.id">
                <td class="mono strong">{{ r.id }}</td>
                <td class="mono">{{ r.type }}</td>
                <td>{{ r.presence }}</td>
                <td>
                  <span class="mono">{{ r.value }}</span>
                  <span v-if="r.note" class="note">{{ r.note }}</span>
                </td>
              </tr>
            </tbody>
          </table>

          <template v-if="view.secrets.length">
            <h4 class="section-label">Held by the wallet, not in the attestation</h4>
            <table>
              <tbody>
                <tr v-for="r in view.secrets" :key="r.id">
                  <td class="mono strong">{{ r.id }}</td>
                  <td class="mono">{{ r.type }}</td>
                  <td>{{ r.value }}</td>
                  <td><span class="note">{{ r.note }}</span></td>
                </tr>
              </tbody>
            </table>
          </template>

          <ul class="notes">
            <li v-for="n in view.notes" :key="n">{{ n }}</li>
          </ul>

          <button type="button" class="raw-toggle" @click="showRaw = !showRaw">{{ showRaw ? 'Hide' : 'Show' }} full structure</button>
          <DevJsonView v-if="showRaw" :value="view.structure" class="raw" />
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.backdrop { position: fixed; inset: 0; z-index: 100; background: rgba(17, 17, 17, 0.28); display: grid; place-items: center; padding: 24px; }
.win {
  width: min(860px, 100%);
  max-height: min(86vh, 900px);
  overflow: auto;
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 12px;
  box-shadow: 0 30px 80px -20px rgba(0, 0, 0, 0.35);
  padding: 18px 22px 22px;
}
header { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
.seg { display: inline-flex; gap: 2px; padding: 3px; background: var(--surface); border: 1px solid var(--line); border-radius: 9px; }
.seg button { border: 0; border-radius: 6px; background: transparent; padding: 5px 12px; font-size: 12.5px; color: var(--muted); }
.seg button.on { background: var(--bg); color: var(--ink); font-weight: 600; box-shadow: 0 0 0 1px var(--line); }
.close { font-size: 12.5px; padding: 4px 10px; border-radius: 7px; border: 1px solid var(--line); background: var(--bg); color: var(--ink-2); }
.close:hover { border-color: var(--ink); }
h3 { margin: 16px 0 4px; font-size: 18px; font-weight: 600; letter-spacing: -0.01em; }
.type { margin: 0 0 14px; font-size: 13px; color: var(--muted); }
.type code { color: var(--ink); font-size: 12.5px; margin-left: 4px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; font-size: 11px; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); padding: 6px 10px 6px 0; border-bottom: 1px solid var(--line); }
td { padding: 8px 10px 8px 0; border-bottom: 1px solid var(--line-2); vertical-align: top; color: var(--ink-2); }
td.mono { font-size: 12px; }
td .mono { font-size: 12px; color: var(--ink); }
.strong { color: var(--ink); font-weight: 600; }
.note { display: block; font-size: 12px; color: var(--muted); margin-top: 2px; }
h4 { margin: 18px 0 2px; }
.notes { margin: 16px 0 0; padding-left: 18px; font-size: 12.5px; color: var(--muted); line-height: 1.6; }
.raw-toggle { margin-top: 12px; background: none; border: 0; padding: 0; font-size: 12.5px; color: var(--ink); text-decoration: underline; text-underline-offset: 3px; text-decoration-color: var(--faint); }
.raw { margin-top: 10px; }
.fade-enter-active, .fade-leave-active { transition: opacity 0.12s; }
.fade-enter-from, .fade-leave-to { opacity: 0; }
</style>
