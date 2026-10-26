<script setup lang="ts">
// Shown to logged-out visitors on the home feed and on communities that need only a login.
const props = defineProps<{ title: string }>()
const wallet = useWallet()
</script>

<template>
  <div class="card flex flex-col items-center px-6 py-12 text-center">
    <span class="flex size-12 items-center justify-center rounded-full bg-brand-soft text-brand">
      <AppIcon name="lock" class="size-6" />
    </span>
    <h2 class="mt-4 text-lg font-semibold">{{ props.title }}</h2>
    <div class="mt-3 max-w-md space-y-2 text-left text-sm text-muted">
      <p>Community accounts use a pseudonym from your EU Digital Identity Wallet. We never see your name, date of birth, or any personal information.</p>
      <p>Some communities have an age limit. To enter, you prove your eligibility without revealing any details.</p>
      <p>Every account is bound to an identity attestation issued to a real person, so there are no bot accounts.</p>
    </div>
    <div class="mt-5 flex gap-2">
      <button class="btn-outline" @click="wallet.start({ kind: 'signin', intent: 'signup' })">Sign up</button>
      <button class="btn-primary" @click="wallet.start({ kind: 'signin', intent: 'login' })">Log in</button>
    </div>
  </div>
</template>
