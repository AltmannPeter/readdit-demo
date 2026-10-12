<script setup lang="ts">
import type { CredentialView } from '~/wallet/holder'
import { nymCard, pidCard } from '~/wallet/holder'

const props = defineProps<{ credential: CredentialView | null }>()
defineEmits<{ scan: [] }>()

function openDetails() {
  window.open('/wallet/credential', 'nym-credential', 'popup,width=560,height=860')
}
</script>

<template>
  <div class="flex h-full flex-col px-5 pb-9">
    <p class="pt-3 text-[11px] font-semibold tracking-wider text-w-muted uppercase">EUDI Wallet App</p>
    <h1 class="mt-1 text-2xl font-bold text-w-ink">Credentials</h1>

    <div class="mt-4 space-y-3">
      <WalletCredentialCard :credential="pidCard" tone="light" />
      <button class="block w-full text-left" aria-label="Open Age and pseudonym details" @click="openDetails">
        <WalletCredentialCard :credential="nymCard(props.credential)" />
      </button>
    </div>
    <p v-if="!props.credential" class="mt-3 text-center text-xs text-w-muted">Connecting to the wallet service…</p>

    <button
      class="mt-auto flex h-12 items-center justify-center gap-2 rounded-2xl bg-w-primary text-[15px] font-semibold text-white active:bg-w-strong disabled:opacity-50"
      :disabled="!props.credential"
      @click="$emit('scan')"
    >
      <AppIcon name="qr" class="size-5" />
      Scan QR code
    </button>
  </div>
</template>
