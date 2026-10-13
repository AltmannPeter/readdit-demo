<script setup lang="ts">
import type { CredentialView } from '~/wallet/holder'
import { nymCard, pidCard } from '~/wallet/holder'

// SIROS ID home (src/pages/Home/Home.jsx): "Credentials" with the view toggle, the credential
// cards (horizontal slider with stacked cards, or a list), and the recent history of the shown card.
const props = defineProps<{ credential: CredentialView | null; history: Array<{ audience: string; at: number }> }>()
const emit = defineEmits<{ scan: []; open: [] }>()

const view = ref<'slider' | 'list'>('slider')
const index = ref(0)
const cards = computed(() => [nymCard(props.credential), pidCard])
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

      <p v-if="!props.credential" class="px-6 py-4 text-center text-xs text-sid-gray-700">Loading...</p>

      <!-- horizontal slider: the shown card on top, the other one stacked behind it -->
      <div v-else-if="view === 'slider'" class="overflow-hidden px-6 py-4">
        <div class="relative">
          <div class="pointer-events-none absolute inset-0 translate-x-2 rotate-2 opacity-90">
            <WalletCard :credential="cards[1 - index]!" class="shadow-md" />
          </div>
          <button
            v-if="index === 0"
            class="relative block w-full rounded-xl text-left shadow-md transition-shadow hover:shadow-lg"
            aria-label="Open Age and pseudonym details"
            @click="emit('open')"
          >
            <WalletCard :credential="cards[0]!" />
          </button>
          <div v-else class="relative rounded-xl shadow-md"><WalletCard :credential="cards[1]!" /></div>
          <button
            class="absolute top-1/2 left-1 z-10 -translate-y-1/2 rounded-md bg-sid-gray-800 p-2 text-white"
            :class="index === 0 ? 'cursor-not-allowed opacity-50' : 'opacity-80 hover:opacity-100'"
            aria-label="Previous credential"
            :disabled="index === 0"
            @click="index = 0"
          >
            <WalletSirosIcon name="chevron-left" class="size-4" />
          </button>
          <button
            class="absolute top-1/2 right-1 z-10 -translate-y-1/2 rounded-md bg-sid-gray-800 p-2 text-white"
            :class="index === 1 ? 'cursor-not-allowed opacity-50' : 'opacity-80 hover:opacity-100'"
            aria-label="Next credential"
            :disabled="index === 1"
            @click="index = 1"
          >
            <WalletSirosIcon name="chevron-right" class="size-4" />
          </button>
          <span class="absolute bottom-3 left-2 z-10 rounded bg-sid-gray-800 px-2 py-1 text-xs text-white">{{ index + 1 }}/{{ cards.length }}</span>
        </div>
      </div>

      <!-- list -->
      <div v-else class="grid grid-cols-1 gap-4 px-6 py-4">
        <button class="block rounded-xl text-left shadow-md hover:shadow-lg" aria-label="Open Age and pseudonym details" @click="emit('open')">
          <WalletCard :credential="cards[0]!" />
        </button>
        <div class="rounded-xl shadow-md"><WalletCard :credential="cards[1]!" /></div>
      </div>

      <div v-if="props.credential && (view === 'list' || index === 0) && props.history.length" class="w-full px-6 py-2">
        <h3 class="my-2 font-semibold text-sid-gray-900">Recent History</h3>
        <div class="space-y-2">
          <WalletButton v-for="h in props.history.slice(0, 3)" :key="h.at" variant="outline" class="w-full">
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
