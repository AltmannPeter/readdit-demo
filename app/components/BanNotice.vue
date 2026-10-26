<script setup lang="ts">
const { bannedHandle, dismissBanNotice } = useAccount()
</script>

<template>
  <div v-if="bannedHandle" class="border-b border-adult/30 bg-adult/10">
    <div class="mx-auto flex max-w-[1280px] items-center gap-3 px-4 py-2.5 text-sm">
      <AppIcon name="ban" class="size-5 shrink-0 text-adult" />
      <p class="flex-1">
        <span class="font-semibold">u/{{ bannedHandle }}</span> has been banned from Community by the moderators.
      </p>
      <button class="rounded-full p-1 text-muted hover:bg-black/5" aria-label="Dismiss" @click="dismissBanNotice">
        <AppIcon name="close" class="size-4" />
      </button>
    </div>
  </div>
</template>
