<script setup lang="ts">
// SIROS ID presentations of one credential on a phone (src/pages/Home/CredentialHistory.jsx): back
// arrow, "Presentations", and the list of presentations (verifier and time), or "No presentations
// found" (pageHistory.noFound).
const props = defineProps<{ history: Array<{ audience: string; at: number }> }>()
const emit = defineEmits<{ back: []; scan: [] }>()
const fmt = (t: number) => new Date(t).toLocaleString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
</script>

<template>
  <div class="flex h-full flex-col bg-white">
    <WalletAppHeader />
    <div class="min-h-0 flex-1 overflow-y-auto px-6 py-6">
      <div class="flex">
        <button class="mr-2 mb-2 text-sid-gray-900" aria-label="Back" @click="emit('back')">
          <WalletSirosIcon name="arrow-left" class="size-5" />
        </button>
        <WalletH1 heading="Presentations" :hr="false" />
      </div>
      <p v-if="!props.history.length" class="text-sid-gray-900">No presentations found</p>
      <div v-else class="space-y-2">
        <WalletButton v-for="h in props.history" :key="h.at" variant="outline" class="w-full">
          <div class="w-full text-left">
            <div class="font-bold">{{ h.audience }}</div>
            <div>{{ fmt(h.at) }}</div>
          </div>
        </WalletButton>
      </div>
    </div>
    <WalletBottomNav active="credentials" @credentials="emit('back')" @scan="emit('scan')" />
  </div>
</template>
