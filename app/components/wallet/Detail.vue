<script setup lang="ts">
import type { CredentialView } from '~/wallet/holder'
import { nymCard } from '~/wallet/holder'

// SIROS ID credential page on a phone (src/pages/Home/Credential.jsx, CredentialInfo.jsx): back
// arrow and name, the card, the claims as "label: value" rows with the wallet's own labels
// (Birth Date, Issuance Date, Expiry Date), and the Presentations button. The wallet's Dataset
// button, which shows the raw claims, is left out.
const props = defineProps<{ credential: CredentialView }>()
const emit = defineEmits<{ back: []; scan: []; presentations: [] }>()

const date = (iso: string) =>
  new Date(iso.length === 10 ? `${iso}T00:00:00Z` : iso).toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric', timeZone: 'UTC' })
const rows = computed(() => {
  const c = props.credential
  return [
    { label: 'Birth Date', value: date(c.attributes.birth_date) },
    { label: 'Issuance Date', value: date(c.validity.signed) },
    { label: 'Expiry Date', value: date(c.validity.validUntil) },
  ]
})
</script>

<template>
  <div class="flex h-full flex-col bg-white">
    <WalletAppHeader />
    <div class="min-h-0 flex-1 overflow-y-auto px-6 py-6">
      <div class="flex">
        <button class="mr-2 mb-2 text-sid-gray-900" aria-label="Back" @click="emit('back')">
          <WalletSirosIcon name="arrow-left" class="size-5" />
        </button>
        <WalletH1 :heading="props.credential.title" :hr="false" />
      </div>
      <div class="flex w-full flex-col gap-4 px-2">
        <div class="relative w-full overflow-hidden rounded-lg shadow-md">
          <WalletCard :credential="nymCard(props.credential)" />
        </div>
        <div class="flex w-full flex-col gap-1 text-sm">
          <div v-for="r in rows" :key="r.label" class="flex flex-row rounded px-2 py-1">
            <div class="w-1/2 font-semibold break-words text-sid-gray-900">{{ r.label }}:</div>
            <div class="w-1/2 break-all text-sid-gray-800">{{ r.value }}</div>
          </div>
        </div>
        <WalletButton variant="primary" class="my-2 w-full" @click="emit('presentations')">Presentations</WalletButton>
      </div>
    </div>
    <WalletBottomNav active="credentials" @credentials="emit('back')" @scan="emit('scan')" />
  </div>
</template>
