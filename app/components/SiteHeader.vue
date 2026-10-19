<script setup lang="ts">
const { account, memberships } = useAccount()
const wallet = useWallet()
/** Logged in somewhere: Readdit, or only a community with its own pseudonym. */
const signedIn = computed(() => !!account.value || Object.values(memberships.value).some((m) => !m.banned))
</script>

<template>
  <header class="sticky top-0 z-30 h-14 border-b border-line bg-surface">
    <div class="mx-auto flex h-full max-w-[1280px] items-center gap-4 px-4">
      <NuxtLink to="/" class="flex shrink-0 items-center gap-2">
        <AppLogo class="size-8" />
        <span class="text-lg font-bold tracking-tight">readdit</span>
      </NuxtLink>

      <label class="mx-auto hidden h-10 w-full max-w-lg items-center gap-2 rounded-full bg-canvas px-4 text-muted md:flex">
        <AppIcon name="search" class="size-4 shrink-0" />
        <input
          type="search"
          placeholder="Search Readdit"
          class="w-full bg-transparent text-sm text-ink outline-none placeholder:text-muted"
        />
      </label>

      <div class="ml-auto flex shrink-0 items-center gap-2">
        <template v-if="!signedIn">
          <button class="btn-outline" @click="wallet.start({ kind: 'signin', intent: 'signup' })">Sign up</button>
          <button class="btn-primary" @click="wallet.start({ kind: 'signin', intent: 'login' })">Log in</button>
        </template>
        <UserMenu v-else />
      </div>
    </div>
  </header>
</template>
