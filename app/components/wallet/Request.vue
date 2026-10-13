<script setup lang="ts">
import type { ConsentView } from '~/wallet/engine'

// SIROS ID presentation request (src/components/flows/PresentCredentialsFlow, PresentationOverviewScreen):
// "Request to Share Data", the requester's name and domain, the requested information in a box
// headed by the credential, and Share / Decline in a fixed bar. The fields come from the request
// (app/wallet/engine.ts, consentFor).
const props = defineProps<{ consent: ConsentView; credentialTitle: string }>()
defineEmits<{ accept: []; cancel: [] }>()
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
                <h3 class="font-bold">{{ props.credentialTitle }}</h3>
                <WalletSirosIcon name="id-card" class="size-6" />
              </div>
              <dl>
                <template v-for="(f, i) in props.consent.fields" :key="f.name">
                  <dt class="font-bold" :class="i > 0 && 'mt-2 pt-2'">{{ f.name }}</dt>
                  <dd class="mt-2 break-words">{{ f.value }}</dd>
                </template>
              </dl>
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
