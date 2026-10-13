<script setup lang="ts">
// SIROS ID bottom navigation (src/components/Layout/Navigation/BottomNav.jsx). At phone widths
// under 360 px the reference hides the labels (`hidden 2xs:block`), so only icons show. Add, Share
// and More are not part of this demo.
defineProps<{ active?: 'credentials' }>()
const emit = defineEmits<{ credentials: []; scan: [] }>()
</script>

<template>
  <nav class="flex shrink-0 items-center justify-around border-t border-sid-gray-400 bg-white px-4 pt-4 pb-7" aria-label="Wallet">
    <button class="relative flex w-[20%] flex-col items-center gap-1 text-sid-gray-900" aria-label="Credentials" @click="emit('credentials')">
      <WalletSirosIcon name="wallet" class="size-5" />
      <span v-if="active === 'credentials'" class="absolute -bottom-3 left-1/2 size-2 -translate-x-1/2 rounded-full bg-sid-brand-lighter" />
    </button>
    <span class="flex w-[20%] flex-col items-center gap-1 text-sid-gray-700" aria-hidden="true">
      <WalletSirosIcon name="circle-plus" class="size-5" />
    </span>
    <button class="relative rounded-full bg-black p-3 text-white shadow-lg" aria-label="Scan QR code" @click="emit('scan')">
      <WalletSirosIcon name="qr-code" class="size-5" />
    </button>
    <span class="flex w-[20%] flex-col items-center gap-1 text-sid-gray-700" aria-hidden="true">
      <WalletSirosIcon name="circle-arrow-right" class="size-5" />
    </span>
    <span class="flex w-[20%] flex-col items-center gap-1 text-sid-gray-700" aria-hidden="true">
      <WalletSirosIcon name="circle-ellipsis" class="size-5" />
    </span>
  </nav>
</template>
