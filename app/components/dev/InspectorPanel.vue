<script setup lang="ts">
// Collapsible developer detail under the diagram: DCQL, request, response, checks. All from the
// session on screen (GET /api/dev/latest).
import { checksOf } from '~/dev/flow'

const open = defineModel<boolean>('open', { default: false })
const { state } = useDevFlow()
const session = computed(() => state.value.session)

type Tab = 'dcql' | 'request' | 'response' | 'checks'
const tab = ref<Tab>('dcql')
const tabs: { id: Tab; label: string }[] = [
  { id: 'dcql', label: 'DCQL' },
  { id: 'request', label: 'Request' },
  { id: 'response', label: 'Response' },
  { id: 'checks', label: 'Checks' },
]
const checks = computed(() => (session.value ? checksOf(session.value) : []))
const passed = computed(() => checks.value.filter((c) => c.status === 'pass').length)
const qr = computed(() => {
  const u = session.value?.authorizationUrl
  if (!u) return null
  const q = new URLSearchParams(u.slice(u.indexOf('?') + 1))
  return { uri: u, client_id: q.get('client_id'), request_uri: q.get('request_uri'), request_uri_method: q.get('request_uri_method') }
})
const errorResponse = computed(() => session.value?.trace.find((t) => t.step === 'response' && t.data?.error)?.data)
</script>

<template>
  <section :class="['insp', { open }]">
    <div class="bar">
      <button type="button" class="toggle" :aria-expanded="open" @click="open = !open">
        <span class="section-label">Inspector</span>
        <span class="hint">{{ open ? 'Hide' : 'Show' }}</span>
      </button>
      <nav v-if="open" class="tabs" role="tablist">
        <button
          v-for="t in tabs"
          :key="t.id"
          type="button"
          role="tab"
          :aria-selected="tab === t.id"
          :class="{ on: tab === t.id }"
          @click="tab = t.id"
        >
          {{ t.label }}<span v-if="t.id === 'checks' && checks.length" class="n mono">{{ passed }}/{{ checks.length }}</span>
        </button>
      </nav>
      <span v-if="open && session" class="sid mono">session {{ session.id.slice(0, 8) }}</span>
    </div>

    <div v-if="open" class="body">
      <template v-if="tab === 'dcql'">
        <DevJsonView v-if="session" :value="session.dcql" />
        <p v-else class="empty">Press Request to see the DCQL query.</p>
      </template>
      <template v-else-if="tab === 'request'">
        <div v-if="session" class="stack">
          <h4 class="section-label">QR payload</h4>
          <DevJsonView :value="qr" />
          <template v-if="session.request">
            <h4 class="section-label">Request object header</h4>
            <DevJsonView :value="session.requestJwsHeader" />
            <h4 class="section-label">Request object claims</h4>
            <DevJsonView :value="session.request" />
          </template>
          <p v-else class="empty">The wallet has not fetched the request yet.</p>
          <h4 class="section-label">Response encryption key (client_metadata.jwks)</h4>
          <DevJsonView :value="session.responseKey" />
        </div>
        <p v-else class="empty">No request yet.</p>
      </template>
      <template v-else-if="tab === 'response'">
        <div v-if="session?.response" class="stack">
          <h4 class="section-label">JWE header</h4>
          <DevJsonView :value="session.response.jwe" />
          <template v-if="session.response.presentation">
            <h4 class="section-label">Decrypted response</h4>
            <DevJsonView :value="{ vp_token: { [session.answered ?? 'query']: [session.response.presentation.base64url] }, state: session.request?.state }" />
            <h4 class="section-label">ZkpPresentation (CBOR)</h4>
            <DevJsonView :value="session.response.presentation.decoded" />
          </template>
          <template v-else-if="errorResponse">
            <h4 class="section-label">Decrypted response</h4>
            <DevJsonView :value="{ error: errorResponse.error, state: session.request?.state }" />
          </template>
          <template v-if="session.outcome?.ok">
            <h4 class="section-label">Verified results</h4>
            <DevJsonView :value="{ system_id: session.outcome.proofId, nym: session.outcome.pseudonym, ...(session.outcome.age && { age: true }) }" />
          </template>
        </div>
        <div v-else-if="errorResponse" class="stack">
          <h4 class="section-label">Unencrypted error response</h4>
          <DevJsonView :value="errorResponse" />
        </div>
        <p v-else class="empty">Waiting for the wallet's response.</p>
      </template>
      <template v-else>
        <DevChecksList v-if="checks.length" :checks="checks" />
        <p v-else class="empty">Checks run once the wallet responds.</p>
      </template>
    </div>
  </section>
</template>

<style scoped>
.insp { border: 1px solid var(--line); border-radius: var(--radius); background: var(--bg); display: flex; flex-direction: column; min-height: 0; }
.insp.open { height: 38vh; min-height: 240px; }
.bar { display: flex; align-items: center; gap: 16px; padding: 0 14px; min-height: 42px; border-bottom: 1px solid transparent; }
.open .bar { border-bottom-color: var(--line); }
.toggle { display: flex; align-items: baseline; gap: 10px; background: none; border: 0; padding: 12px 0; }
.hint { font-size: 12.5px; color: var(--muted); }
.toggle:hover .hint { color: var(--ink); }
.tabs { display: flex; gap: 2px; }
.tabs button { background: none; border: 0; padding: 12px 8px 10px; font-size: 13px; color: var(--muted); border-bottom: 2px solid transparent; margin-bottom: -1px; }
.tabs button:hover { color: var(--ink); }
.tabs button.on { color: var(--ink); border-bottom-color: var(--ink); }
.n { margin-left: 6px; font-size: 11px; color: var(--faint); }
.sid { margin-left: auto; font-size: 11.5px; color: var(--faint); }
.body { flex: 1; min-height: 0; overflow: auto; padding: 14px; }
.stack { display: flex; flex-direction: column; gap: 6px; }
h4 { margin: 10px 0 0; }
h4:first-child { margin-top: 0; }
.empty { margin: 4px 0; color: var(--muted); font-size: 13px; }
</style>
