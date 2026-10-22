<script setup lang="ts">
const { account, memberships } = useAccount()
const wallet = useWallet()
/** Logged in somewhere: Community, or only a community with its own pseudonym. */
const signedIn = computed(() => !!account.value || Object.values(memberships.value).some((m) => !m.banned))
</script>

<template>
  <header class="sticky top-0 z-30 h-14 border-b border-line bg-surface">
    <div class="mx-auto flex h-full max-w-[1280px] items-center gap-4 px-4">
      <NuxtLink to="/" class="flex shrink-0 items-center gap-2">
        <AppLogo class="size-8" />
        <span class="text-lg font-bold tracking-tight">community</span>
      </NuxtLink>

      <div class="ml-auto flex shrink-0 items-center gap-2">
        <ViewSwitch class="mr-2" />
        <template v-if="!signedIn">
          <button class="btn-outline" @click="wallet.start({ kind: 'signin', intent: 'signup' })">Sign up</button>
          <button class="btn-primary" @click="wallet.start({ kind: 'signin', intent: 'login' })">Log in</button>
        </template>
        <UserMenu v-else />
      </div>
    </div>
  </header>
</template>
