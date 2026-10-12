<script setup lang="ts">
defineProps<{ url: string | null }>()
defineEmits<{ cancel: [] }>()
</script>

<template>
  <div class="absolute inset-0 flex flex-col items-center text-white">
    <p class="mt-8 text-sm font-medium text-white/80">Point the camera at the QR code</p>
    <div class="relative mt-10 size-[200px]">
      <span class="absolute top-0 left-0 size-7 rounded-tl-xl border-t-[3px] border-l-[3px] border-white" />
      <span class="absolute top-0 right-0 size-7 rounded-tr-xl border-t-[3px] border-r-[3px] border-white" />
      <span class="absolute bottom-0 left-0 size-7 rounded-bl-xl border-b-[3px] border-l-[3px] border-white" />
      <span class="absolute right-0 bottom-0 size-7 rounded-br-xl border-r-[3px] border-b-[3px] border-white" />
      <div
        v-if="url"
        class="absolute inset-6 rounded bg-white p-2 opacity-90"
        style="transform: perspective(500px) rotateX(10deg) rotateZ(-4deg)"
      >
        <QrCode :value="url" />
      </div>
      <span class="animate-scanline absolute inset-x-3 top-6 h-0.5 rounded bg-sky-300/80 shadow-[0_0_12px_2px_rgba(125,211,252,0.6)]" />
    </div>
    <button class="mt-auto mb-12 text-sm font-semibold text-white/80" @click="$emit('cancel')">Cancel</button>
  </div>
</template>
