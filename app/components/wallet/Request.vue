<script setup lang="ts">
import type { ConsentView } from '~/wallet/engine'
import { sidDate } from '~/wallet/holder'

// SIROS ID presentation request (src/components/flows/PresentCredentialsFlow, PresentationOverviewScreen):
// "Request to Share Data", the requester's name and domain, the requested information in a box
// headed by the credential, "Switch credential" with the number of other matching credentials
// when there are any, and Share / Decline in a fixed bar. The fields come from the request
// (app/wallet/engine.ts, consentFor). Under its header the box shows the chosen credential's birth
// date, which tells two credentials of the same type apart; it stays on the phone, and is not among
// the requested information.
const props = defineProps<{ consent: ConsentView; credentialTitle: string; birthDate?: string; validUntil?: string; alternatives?: number }>()
defineEmits<{ accept: []; cancel: []; switch: [] }>()
const birth = computed(() => (props.birthDate ? sidDate(props.birthDate) : ''))
const expiry = computed(() => (props.validUntil ? sidDate(props.validUntil) : ''))
</script>

<template>
  <div class="flex h-full flex-col bg-white">
    <WalletAppHeader />
    <div class="min-h-0 flex-1 overflow-y-auto px-6 pb-6 text-sid-gray-900">
      <div class="mt-4"><WalletH1 heading="Request to Share Data" /></div>
      <dl>
        <dt class="font-bold">Requester</dt>
        <dd class="mt-2">{{ props.consent.verifier.name }}</dd>
        <dd class="mt-2">{{ props.consent.verifier.host }}</dd>
      </dl>

      <div class="mt-4">
        <h2 class="font-bold">Requested Information</h2>
        <ul>
          <li class="mt-2">
            <div class="flex flex-col gap-4 rounded-md border border-sid-gray-700 p-4">
              <div class="flex items-center justify-between rounded-md bg-sid-brand px-3 py-1 text-white">
                <h3 class="font-bold" aria-live="polite">{{ props.credentialTitle }}</h3>
                <WalletSirosIcon name="id-card" class="size-6" />
              </div>
              <div v-if="birth || expiry" class="-mt-2 text-sm">
                <p v-if="birth" class="font-semibold text-sid-gray-900">Birth Date: {{ birth }}</p>
                <p v-if="expiry" class="text-xs text-sid-gray-700">Expiry Date: {{ expiry }}</p>
              </div>
              <dl>
                <template v-for="(f, i) in props.consent.fields" :key="f.name">
                  <dt class="font-bold" :class="i > 0 && 'mt-2 pt-2'">{{ f.name }}</dt>
                  <dd class="mt-2 break-words">{{ f.value }}</dd>
                </template>
              </dl>
              <div v-if="props.alternatives" class="-mx-4 border-t border-t-sid-gray-600 px-4 pt-4 pb-1">
                <button
                  class="flex items-center gap-1 font-medium text-sid-brand underline-offset-2 hover:underline"
                  :aria-label="`Switch credential: ${props.credentialTitle}, ${props.alternatives + 1} available`"
                  @click="$emit('switch')"
                >
                  Switch credential
                  <svg viewBox="0 0 24 24" stroke-width="2" class="size-6" aria-hidden="true">
                    <rect x="4" y="4" width="19" height="14" rx="2" fill="transparent" class="stroke-sid-gray-700" />
                    <rect x="2" y="7" width="19" height="14" rx="2" class="fill-sid-gray-700" />
                    <text x="11" y="18" text-anchor="middle" font-size="12" font-weight="600" fill="#fff">{{ props.alternatives }}</text>
                  </svg>
                </button>
              </div>
            </div>
          </li>
        </ul>
      </div>
    </div>
    <div
      class="relative flex shrink-0 flex-col gap-4 bg-white px-6 pt-4 pb-8 before:pointer-events-none before:absolute before:right-0 before:bottom-full before:left-0 before:h-8 before:bg-linear-to-t before:from-white before:to-transparent before:content-['']"
    >
      <WalletButton variant="primary" size="lg" @click="$emit('accept')">Share</WalletButton>
      <WalletButton variant="outline" size="lg" @click="$emit('cancel')">Decline</WalletButton>
    </div>
  </div>
</template>
