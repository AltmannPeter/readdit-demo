<script setup lang="ts">
// SIROS ID QR scanner (src/components/QRCodeScanner/QRCodeScanner.jsx), full screen on a phone:
// back arrow and "Scan the QR Code", the camera view with the white scan region, the zoom row.
// The camera sees the QR code on the website's screen; once read, a green check shows.
defineProps<{ url: string | null; detected: boolean }>()
defineEmits<{ cancel: [] }>()
</script>

<template>
  <div class="flex h-full flex-col bg-white">
    <WalletAppHeader />
    <div class="flex min-h-0 flex-1 flex-col px-6 pt-6 pb-8">
      <div class="flex">
        <button class="mr-2 mb-2 text-sid-gray-900" aria-label="Cancel scan" @click="$emit('cancel')">
          <WalletSirosIcon name="arrow-left" class="size-5" />
        </button>
        <WalletH1 heading="Scan the QR Code" :hr="false" />
      </div>
      <div class="relative mt-4 flex h-[300px] w-full items-center justify-center overflow-hidden bg-gradient-to-b from-[#2a2f36] to-[#15181c]">
        <div v-if="url" class="w-[150px] rounded bg-white p-2 opacity-90" style="transform: perspective(500px) rotateX(12deg) rotateZ(-4deg)">
          <QrCode :value="url" />
        </div>
        <!-- the scan region: a white square with corner marks -->
        <div class="pointer-events-none absolute size-[190px]">
          <span class="absolute top-0 left-0 size-6 border-t-4 border-l-4 border-white" />
          <span class="absolute top-0 right-0 size-6 border-t-4 border-r-4 border-white" />
          <span class="absolute bottom-0 left-0 size-6 border-b-4 border-l-4 border-white" />
          <span class="absolute right-0 bottom-0 size-6 border-r-4 border-b-4 border-white" />
        </div>
        <WalletSirosIcon v-if="detected" name="check-circle" class="absolute size-[100px] text-green-600" />
      </div>
      <div class="my-4 flex w-full items-center">
        <WalletSirosIcon name="zoom-out" class="mt-2 mr-2 size-[30px] text-sid-gray-800" />
        <input type="range" min="1" max="3" step="0.1" value="1" class="mt-2 h-2 w-full cursor-pointer rounded-lg bg-sid-gray-200" aria-label="Zoom" />
        <WalletSirosIcon name="zoom-in" class="mt-2 ml-2 size-[30px] text-sid-gray-800" />
      </div>
    </div>
  </div>
</template>
