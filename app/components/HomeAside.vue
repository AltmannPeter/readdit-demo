<script setup lang="ts">
const { account } = useAccount()
const wallet = useWallet()
</script>

<template>
  <div v-if="!account" class="card p-4">
    <h2 class="font-semibold">Welcome to Readdit</h2>
    <p class="mt-2 text-sm leading-relaxed text-muted">
      Sign up with your EU Digital Identity Wallet. Your account uses a pseudonym that is valid only on Readdit, with no email address or password.
    </p>
    <div class="mt-4 grid gap-2">
      <button class="btn-outline w-full" @click="wallet.start({ kind: 'signin', intent: 'signup' })">Sign up</button>
      <button class="btn-primary w-full" @click="wallet.start({ kind: 'signin', intent: 'login' })">Log in</button>
    </div>
  </div>

  <div v-else class="card p-4">
    <div class="flex items-center gap-3">
      <UserAvatar :seed="account.handle" size="lg" />
      <div class="min-w-0">
        <p class="truncate font-semibold">u/{{ account.handle }}</p>
        <p class="text-xs text-muted">Joined {{ account.joinedAt }}</p>
      </div>
    </div>
    <dl class="mt-4 space-y-2 text-sm">
      <div class="flex items-center justify-between">
        <dt class="text-muted">Account</dt>
        <dd class="font-medium">Pseudonymous</dd>
      </div>
      <div class="flex items-center justify-between">
        <dt class="text-muted">Age checks</dt>
        <dd class="font-medium">
          <template v-if="account.ageProofs.length">
            <span v-for="p in account.ageProofs" :key="p.label + p.at" class="ml-1">{{ p.label }}</span>
          </template>
          <template v-else>None</template>
        </dd>
      </div>
    </dl>
  </div>
</template>
