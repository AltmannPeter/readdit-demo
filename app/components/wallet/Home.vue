<script setup lang="ts">
import type { CredentialView } from '~/wallet/holder'
import { nymCard, pidCard, sidDate } from '~/wallet/holder'

// SIROS ID home (src/pages/Home/Home.jsx): "Credentials" with the view toggle, the credential
// cards (horizontal slider with stacked cards, or a list), and the recent history of the shown card.
// The wallet's nym_auth credentials come first; the Personal ID card only makes the wallet look
// lived-in and opens nothing.
const props = defineProps<{ credentials: CredentialView[] | null; history: Array<{ audience: string; at: number; credential: number }> }>()
const emit = defineEmits<{ scan: []; open: [index: number] }>()

const view = ref<'slider' | 'list'>('slider')
const index = ref(0)
const cards = computed(() => [...(props.credentials ?? []).map((c) => ({ display: nymCard(c), credential: c })), { display: pidCard, credential: null }])
const shown = computed(() => cards.value[index.value]!)
const behind = computed(() => cards.value[(index.value + 1) % cards.value.length]!)
/** The shown card's presentations in the slider; every credential's in the list. */
const recent = computed(() => {
  if (view.value === 'list') return props.history.slice(0, 3)
  const c = shown.value.credential
  return c ? props.history.filter((h) => h.credential === c.index).slice(0, 3) : []
})
const born = (iso?: string) => (iso ? `, birth date ${sidDate(iso)}` : '')
const fmt = (t: number) => new Date(t).toLocaleString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
</script>

<template>
  <div class="flex h-full flex-col bg-white">
    <WalletAppHeader />
    <div class="min-h-0 flex-1 overflow-y-auto py-6">
      <div class="px-6">
        <WalletH1 heading="Credentials">
          <WalletButton variant="outline" size="sm" class="mb-2" aria-label="Change view" @click="view = view === 'slider' ? 'list' : 'slider'">
            <WalletSirosIcon :name="view === 'slider' ? 'gallery-horizontal' : 'rows-2'" class="size-5" />
            View
          </WalletButton>
        </WalletH1>
        <hr class="mb-2 border-t border-sid-gray-400" />
      </div>

      <p v-if="!props.credentials" class="px-6 py-4 text-center text-xs text-sid-gray-700">Loading...</p>

      <!-- horizontal slider: the shown card on top, the next one stacked behind it -->
      <div v-else-if="view === 'slider'" class="overflow-hidden px-6 py-4">
        <div class="relative">
          <div class="pointer-events-none absolute inset-0 translate-x-2 rotate-2 opacity-90">
            <WalletCard :credential="behind.display" class="shadow-md" />
          </div>
          <button
            v-if="shown.credential"
            class="relative block w-full rounded-xl text-left shadow-md transition-shadow hover:shadow-lg"
            :aria-label="`Open ${shown.display.title} details${born(shown.display.birthDate)}`"
            @click="emit('open', shown.credential.index)"
          >
            <WalletCard :credential="shown.display" />
          </button>
          <div v-else class="relative rounded-xl shadow-md"><WalletCard :credential="shown.display" /></div>
          <button
            class="absolute top-1/2 left-1 z-10 -translate-y-1/2 rounded-md bg-sid-gray-800 p-2 text-white"
            :class="index === 0 ? 'cursor-not-allowed opacity-50' : 'opacity-80 hover:opacity-100'"
            aria-label="Previous credential"
            :disabled="index === 0"
            @click="index--"
          >
            <WalletSirosIcon name="chevron-left" class="size-4" />
          </button>
          <button
            class="absolute top-1/2 right-1 z-10 -translate-y-1/2 rounded-md bg-sid-gray-800 p-2 text-white"
            :class="index === cards.length - 1 ? 'cursor-not-allowed opacity-50' : 'opacity-80 hover:opacity-100'"
            aria-label="Next credential"
            :disabled="index === cards.length - 1"
            @click="index++"
          >
            <WalletSirosIcon name="chevron-right" class="size-4" />
          </button>
          <span class="absolute bottom-3 left-2 z-10 rounded bg-sid-gray-800 px-2 py-1 text-xs text-white">{{ index + 1 }}/{{ cards.length }}</span>
        </div>
      </div>

      <!-- list -->
      <div v-else class="grid grid-cols-1 gap-4 px-6 py-4">
        <template v-for="(card, k) in cards" :key="k">
          <button
            v-if="card.credential"
            class="block rounded-xl text-left shadow-md hover:shadow-lg"
            :aria-label="`Open ${card.display.title} details${born(card.display.birthDate)}`"
            @click="emit('open', card.credential.index)"
          >
            <WalletCard :credential="card.display" />
          </button>
          <div v-else class="rounded-xl shadow-md"><WalletCard :credential="card.display" /></div>
        </template>
      </div>

      <div v-if="recent.length" class="w-full px-6 py-2">
        <h3 class="my-2 font-semibold text-sid-gray-900">Recent History</h3>
        <div class="space-y-2">
          <WalletButton v-for="h in recent" :key="h.at" variant="outline" class="w-full">
            <div class="w-full text-left">
              <div class="font-bold">{{ h.audience }}</div>
              <div>{{ fmt(h.at) }}</div>
            </div>
          </WalletButton>
        </div>
      </div>
    </div>
    <WalletBottomNav active="credentials" @scan="emit('scan')" />
  </div>
</template>
