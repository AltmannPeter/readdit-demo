<script setup lang="ts">
import type { RequestView } from '~/wallet/engine'
import { ageText } from '~/wallet/engine'

defineProps<{ view: RequestView; credentialTitle: string; issuer: string }>()
defineEmits<{ accept: []; cancel: [] }>()
</script>

<template>
  <div class="flex h-full flex-col">
    <div class="min-h-0 flex-1 space-y-3 overflow-y-auto px-4 pt-2 pb-3">
      <p class="px-1 text-[11px] font-semibold tracking-wider text-w-muted uppercase">Request</p>
      <WalletVerifierHeader :name="view.verifierName" :host="view.verifierHost" />

      <p class="px-1 pt-1 text-sm font-semibold text-w-ink">{{ view.verifierName }} asks for:</p>
      <ul class="divide-y divide-w-line rounded-2xl bg-w-surface">
        <li v-for="(item, i) in view.items" :key="i" class="flex gap-3 p-3">
          <span class="flex size-8 shrink-0 items-center justify-center rounded-full bg-w-soft text-w-primary">
            <AppIcon :name="item.kind === 'pseudonym' ? 'user' : 'calendar'" class="size-4" />
          </span>
          <div class="min-w-0">
            <template v-if="item.kind === 'pseudonym'">
              <p class="text-sm font-semibold text-w-ink">A pseudonym for this site</p>
              <p class="text-xs leading-snug text-w-muted">Only used on {{ view.verifierHost }}. Cannot be linked to your other accounts.</p>
            </template>
            <template v-else>
              <p class="text-sm font-semibold text-w-ink">Proof that you are {{ ageText(item) }}</p>
              <p class="text-xs leading-snug text-w-muted">Your date of birth is not shared.</p>
            </template>
          </div>
        </li>
      </ul>

      <div class="flex gap-3 rounded-2xl bg-w-soft/70 p-3">
        <AppIcon name="eyeoff" class="mt-0.5 size-4 shrink-0 text-w-primary" />
        <p class="text-xs leading-snug text-w-ink">Your name, date of birth and other personal data are not shared.</p>
      </div>

      <p class="px-1 text-xs text-w-muted">From: {{ credentialTitle }} · {{ issuer }}</p>
    </div>

    <div class="space-y-1 px-4 pt-2 pb-8">
      <button class="h-12 w-full rounded-2xl bg-w-primary text-[15px] font-semibold text-white active:bg-w-strong" @click="$emit('accept')">
        Continue
      </button>
      <button class="h-10 w-full text-sm font-semibold text-w-primary" @click="$emit('cancel')">Cancel</button>
    </div>
  </div>
</template>
