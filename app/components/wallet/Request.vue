<script setup lang="ts">
import type { ConsentView } from '~/wallet/engine'
import { sidDate } from '~/wallet/holder'

// SIROS ID presentation request (src/components/flows/PresentCredentialsFlow, PresentationOverviewScreen),
// in the layout of SIROS ID's newer design: "Request to Share Data", the requester's domain, then one
// card per item requested (app/wallet/engine.ts, consentFor), the age proof first: an icon tile, the
// title and, for the pseudonym, its site and a dash list of what it means for the person, one line
// each. "Switch credential" with the number of other matching credentials when there are any, and
// Share / Decline in a fixed bar. The birth date is not shown, as it is not shared.
const props = defineProps<{ consent: ConsentView; credentialTitle: string; validUntil?: string; alternatives?: number }>()
defineEmits<{ accept: []; cancel: []; switch: [] }>()
const ICONS = { pseudonym: 'hat-glasses', age: 'calendar-check' } as const
const expiry = computed(() => (props.validUntil ? sidDate(props.validUntil) : ''))
</script>

<template>
  <div class="flex h-full flex-col bg-white">
    <WalletAppHeader />
    <div class="min-h-0 flex-1 overflow-y-auto px-6 pb-6 text-sid-gray-900">
      <div class="mt-4"><WalletH1 heading="Request to Share Data" /></div>
      <dl>
        <dt class="font-bold">Requester</dt>
        <dd class="mt-2">{{ props.consent.verifier.host }}</dd>
      </dl>

      <h2 class="mt-6 font-bold">Requested information</h2>
      <p v-if="expiry" class="mt-1 text-xs text-sid-gray-700">Expiry Date: {{ expiry }}</p>
      <div class="mt-3 flex flex-col gap-3" aria-live="polite">
        <section v-for="f in props.consent.fields" :key="f.name" class="rounded-xl border border-sid-gray-400 bg-white p-3">
          <div class="flex items-center gap-3">
            <span class="flex size-10 shrink-0 items-center justify-center rounded-lg bg-sid-gray-200 text-sid-brand">
              <WalletSirosIcon :name="ICONS[f.kind]" :stroke-width="1.75" class="size-5" />
            </span>
            <div class="min-w-0">
              <h3 class="leading-tight font-bold">{{ f.name }}</h3>
              <p v-if="f.value" class="text-[15px] break-words">{{ f.value }}</p>
            </div>
          </div>
          <template v-if="f.notes?.length">
            <hr class="my-2.5 border-sid-gray-300" />
            <ul class="space-y-1.5 text-xs">
              <li v-for="n in f.notes" :key="n">- {{ n }}</li>
            </ul>
          </template>
        </section>
      </div>
      <button
        v-if="props.alternatives"
        class="mt-3 flex items-center gap-1 font-medium text-sid-brand underline-offset-2 hover:underline"
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
    <div
      class="relative flex shrink-0 flex-col gap-4 bg-white px-6 pt-4 pb-8 before:pointer-events-none before:absolute before:right-0 before:bottom-full before:left-0 before:h-8 before:bg-linear-to-t before:from-white before:to-transparent before:content-['']"
    >
      <WalletButton variant="primary" size="lg" @click="$emit('accept')">Share</WalletButton>
      <WalletButton variant="outline" size="lg" @click="$emit('cancel')">Decline</WalletButton>
    </div>
  </div>
</template>
