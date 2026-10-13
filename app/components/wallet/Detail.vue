<script setup lang="ts">
import type { CredentialView } from '~/wallet/holder'
import { nymCard } from '~/wallet/holder'

// SIROS ID credential page (src/pages/Home/Credential.jsx, CredentialInfo.jsx): back arrow and
// name, the card, the attributes as "label: value" rows, and the "Dataset" button, which opens
// the full details in a separate window.
const props = defineProps<{ credential: CredentialView }>()
const emit = defineEmits<{ back: []; scan: [] }>()

const date = (iso: string) =>
  new Date(iso.length === 10 ? `${iso}T00:00:00Z` : iso).toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric', timeZone: 'UTC' })
// The reference cuts strings over 30 characters without spaces to 30 characters and an ellipsis.
const cut = (s: string) => (s.length > 30 && !s.includes(' ') ? `${s.slice(0, 30)}…` : s)
const rows = computed(() => {
  const c = props.credential
  return [
    { label: 'Date of birth', value: date(c.attributes.birth_date) },
    { label: 'Seed commitment', value: cut(c.attributes.ssc) },
    { label: 'Private seed commitment', value: c.attributes.psc ? cut(c.attributes.psc) : 'Not included' },
    { label: 'Issuer', value: c.issuer.country ? `${c.issuer.name} (${c.issuer.country})` : c.issuer.name },
    { label: 'Valid from', value: date(c.validity.validFrom) },
    { label: 'Valid until', value: date(c.validity.validUntil) },
    { label: 'Device key', value: `${c.deviceKey.kty} ${c.deviceKey.crv}` },
  ]
})

function openDataset() {
  window.open('/wallet/credential', 'nym-credential', 'popup,width=560,height=860')
}
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
        <WalletButton variant="primary" class="my-2 w-full" aria-label="Open the credential details in a new window" @click="openDataset">Dataset</WalletButton>
      </div>
    </div>
    <WalletBottomNav active="credentials" @credentials="emit('back')" @scan="emit('scan')" />
  </div>
</template>
