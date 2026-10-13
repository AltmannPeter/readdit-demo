<script setup lang="ts">
// Generic smartphone. No brand marks; the SIROS ID wallet runs on it.
const time = ref('')
let timer: ReturnType<typeof setInterval> | undefined
const tick = () => {
  const d = new Date()
  time.value = `${d.getHours()}:${String(d.getMinutes()).padStart(2, '0')}`
}
onMounted(() => {
  tick()
  timer = setInterval(tick, 10_000)
})
onBeforeUnmount(() => clearInterval(timer))
</script>

<template>
  <div class="relative h-[620px] w-[300px] shrink-0 select-none">
    <!-- side buttons -->
    <span class="absolute top-[118px] -left-[3px] h-8 w-[3px] rounded-l bg-neutral-700" />
    <span class="absolute top-[166px] -left-[3px] h-14 w-[3px] rounded-l bg-neutral-700" />
    <span class="absolute top-[232px] -left-[3px] h-14 w-[3px] rounded-l bg-neutral-700" />
    <span class="absolute top-[180px] -right-[3px] h-20 w-[3px] rounded-r bg-neutral-700" />

    <div class="h-full w-full rounded-[52px] bg-neutral-900 p-[10px] shadow-2xl ring-1 ring-neutral-700">
      <div class="relative flex h-full w-full flex-col overflow-hidden rounded-[42px] bg-white">
        <!-- status bar -->
        <div class="relative z-20 flex h-11 shrink-0 items-center justify-between bg-white px-7 pt-1 text-[13px] font-semibold text-sid-gray-900">
          <span class="w-12 tabular-nums">{{ time }}</span>
          <span class="absolute top-2.5 left-1/2 h-[26px] w-[92px] -translate-x-1/2 rounded-full bg-black" />
          <span class="flex w-12 items-center justify-end gap-1">
            <svg viewBox="0 0 18 12" class="h-2.5 w-4" fill="currentColor" aria-hidden="true">
              <rect x="0" y="8" width="3" height="4" rx="1" /><rect x="5" y="5.5" width="3" height="6.5" rx="1" />
              <rect x="10" y="3" width="3" height="9" rx="1" /><rect x="15" y="0" width="3" height="12" rx="1" />
            </svg>
            <svg viewBox="0 0 26 12" class="h-2.5 w-5" aria-hidden="true">
              <rect x="0.5" y="0.5" width="22" height="11" rx="3" fill="none" stroke="currentColor" opacity=".4" />
              <rect x="2" y="2" width="16" height="8" rx="1.8" fill="currentColor" />
              <rect x="23.5" y="4" width="1.8" height="4" rx=".9" fill="currentColor" opacity=".4" />
            </svg>
          </span>
        </div>

        <div class="relative min-h-0 flex-1">
          <slot />
        </div>

        <!-- home indicator -->
        <div class="pointer-events-none absolute inset-x-0 bottom-2 z-20 flex justify-center">
          <span class="h-[5px] w-28 rounded-full bg-sid-gray-900/70" />
        </div>
      </div>
    </div>
  </div>
</template>
