<script setup lang="ts">
const { account, refresh } = useAccount()

// Pick up moderator actions (bans) while someone is logged in.
let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  timer = setInterval(() => account.value && refresh(), 3000)
})
onBeforeUnmount(() => clearInterval(timer))
</script>

<template>
  <div class="min-h-screen">
    <SiteHeader />
    <BanNotice />
    <div class="mx-auto flex max-w-[1280px] gap-6 px-4 py-4">
      <aside class="hidden w-60 shrink-0 lg:block">
        <SideNav />
      </aside>
      <main class="min-w-0 flex-1">
        <slot />
      </main>
    </div>
    <WalletModal />
  </div>
</template>
