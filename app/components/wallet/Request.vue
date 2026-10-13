<script setup lang="ts">
import type { ConsentView } from '~/wallet/engine'

// SIROS ID presentation request (src/components/flows/PresentCredentialsFlow): "Request to Share
// Data", the requester, the requested information in a box headed by the credential, and Share /
// Decline in a fixed bar. What it lists comes from the request, the circuit and the credential
// (app/wallet/engine.ts, consentFor).
const props = defineProps<{ consent: ConsentView; credentialTitle: string }>()
defineEmits<{ accept: []; cancel: [] }>()
const short = (hex: string) => `${hex.slice(0, 8)}…${hex.slice(-8)}`
</script>

<template>
  <div class="flex h-full flex-col bg-white">
    <WalletAppHeader />
    <div class="min-h-0 flex-1 overflow-y-auto px-6 pb-6 text-sid-gray-900">
      <div class="mt-4"><WalletH1 heading="Request to Share Data" /></div>
      <dl class="text-[15px]">
        <dt class="font-bold">Requester</dt>
        <dd class="mt-2">{{ props.consent.verifier.name }}</dd>
        <dd class="mt-1">{{ props.consent.verifier.host }}</dd>
        <dd class="mt-1 font-mono text-[11px] break-all text-sid-gray-700">{{ props.consent.verifier.clientId }}</dd>
        <dd v-if="props.consent.verifier.certificate" class="mt-1 flex items-start gap-1 text-xs text-sid-gray-700">
          <WalletSirosIcon name="shield-check" class="mt-px size-3.5 shrink-0 text-sid-green" />
          <span>Request signed by {{ props.consent.verifier.certificate }}</span>
        </dd>
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
                <template v-if="props.consent.pseudonym">
                  <dt class="font-bold">Pseudonym for {{ props.consent.verifier.host }}</dt>
                  <dd class="mt-2 font-mono text-[13px]" :title="props.consent.pseudonym.value">{{ short(props.consent.pseudonym.value) }}</dd>
                  <dd class="mt-2">
                    <ul class="list-disc space-y-1 pl-4 text-xs leading-snug text-sid-gray-800">
                      <li v-for="line in props.consent.pseudonym.lines" :key="line">{{ line }}</li>
                    </ul>
                  </dd>
                </template>
                <template v-if="props.consent.age">
                  <dt class="mt-3 border-t border-sid-gray-400 pt-3 font-bold">Age</dt>
                  <dd class="mt-2 text-[15px]">{{ props.consent.age.text }}</dd>
                  <dd class="mt-1 text-xs text-sid-gray-800">{{ props.consent.age.range }}. {{ props.consent.age.learns }}</dd>
                </template>
              </dl>
            </div>
          </li>
        </ul>
      </div>

      <div class="mt-4">
        <h2 class="font-bold">Also visible to {{ props.consent.verifier.host }}</h2>
        <dl class="mt-1 text-xs leading-snug">
          <div v-for="v in props.consent.alsoVisible" :key="v.label" class="mt-2">
            <dt class="font-semibold">{{ v.label }}</dt>
            <dd class="text-sid-gray-800">{{ v.value }}</dd>
          </div>
        </dl>
      </div>

      <div class="mt-4">
        <h2 class="font-bold">Not shared</h2>
        <ul class="mt-2 space-y-1.5 text-xs">
          <li v-for="n in props.consent.notShared" :key="n.label" class="flex items-start gap-2">
            <WalletSirosIcon name="eye-off" class="mt-px size-3.5 shrink-0 text-sid-gray-700" />
            <span>{{ n.label }}<span v-if="n.value" class="text-sid-gray-700"> ({{ n.value }})</span></span>
          </li>
        </ul>
      </div>
    </div>
    <div
      class="relative flex shrink-0 flex-col gap-3 bg-white px-6 pt-3 pb-8 before:pointer-events-none before:absolute before:right-0 before:bottom-full before:left-0 before:h-8 before:bg-linear-to-t before:from-white before:to-transparent before:content-['']"
    >
      <WalletButton variant="primary" size="lg" @click="$emit('accept')">Share</WalletButton>
      <WalletButton variant="outline" size="lg" @click="$emit('cancel')">Decline</WalletButton>
    </div>
  </div>
</template>
