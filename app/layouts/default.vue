<script setup lang="ts">
const { account, refresh } = useAccount()
const guide = useGuidePanel()

// Pick up moderator actions (bans) while someone is logged in.
let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  timer = setInterval(() => account.value && refresh(), 3000)
})
onBeforeUnmount(() => clearInterval(timer))
</script>

<template>
  <div>
    <div class="min-h-screen" :style="{ marginRight: guide.width.value }">
      <SiteHeader />
      <BanNotice />
      <!-- container queries: the columns follow the width the guide panel leaves, not the window's -->
      <div class="@container">
        <div class="mx-auto flex max-w-[1280px] gap-6 px-4 py-4">
          <aside class="hidden w-60 shrink-0 @5xl:block">
            <SideNav />
          </aside>
          <main class="min-w-0 flex-1">
            <slot />
          </main>
        </div>
      </div>
      <WalletModal />
    </div>
    <GuidePanel />
  </div>
</template>
