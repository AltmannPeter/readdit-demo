<script setup lang="ts">
// No Sign up or Log in here (Peter, 2026-10-23: "One single signup and login is enough"): the page
// offers them (LoginNotice, the gates). Logged in, the account menu.
const { account, memberships } = useAccount()
/** Logged in somewhere: Community, or only a community with its own pseudonym. */
const signedIn = computed(() => !!account.value || Object.values(memberships.value).some((m) => !m.banned))
</script>

<template>
  <header class="sticky top-0 z-30 h-14 border-b border-line bg-surface">
    <div class="mx-auto flex h-full max-w-[1280px] items-center gap-4 px-4">
      <NuxtLink to="/" class="flex shrink-0 items-center gap-2" data-home>
        <AppLogo class="size-8" />
        <span class="text-lg font-bold tracking-tight">community</span>
      </NuxtLink>

      <div class="ml-auto flex shrink-0 items-center gap-2">
        <QuickNav class="mr-1" />
        <ViewSwitch class="mr-2" />
        <UserMenu v-if="signedIn" />
      </div>
    </div>
  </header>
</template>
