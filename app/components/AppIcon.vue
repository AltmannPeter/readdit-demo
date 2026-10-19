<script setup lang="ts">
const props = defineProps<{ name: string; filled?: boolean }>()
const d = computed(() => PATHS[props.name as IconName] ?? '')
</script>

<script lang="ts">
const PATHS = {
  home: 'M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6h-6v6H4a1 1 0 0 1-1-1z',
  up: 'M12 4 4.5 12.5H9V20h6v-7.5h4.5z',
  down: 'M12 20l7.5-8.5H15V4H9v7.5H4.5z',
  comment: 'M5 5h14a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H10l-5 4v-4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1z',
  share: 'M4 13v6a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-6M12 15V3M7.5 7.5 12 3l4.5 4.5',
  lock: 'M6 11h12v9H6zM8.5 11V8a3.5 3.5 0 0 1 7 0v3',
  search: 'M10.5 4a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13zM20 20l-4.8-4.8',
  shield: 'M12 3l7 3v6c0 4.4-3 7.6-7 9-4-1.4-7-4.6-7-9V6zM9 12l2 2 4-4',
  chevron: 'M6 9l6 6 6-6',
  logout: 'M14 4h5v16h-5M10 8l-4 4 4 4M6 12h10',
  close: 'M6 6l12 12M18 6 6 18',
  ban: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM5.6 5.6l12.8 12.8',
  plus: 'M12 5v14M5 12h14',
  phone: 'M8 3h8a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1zM11 18h2',
  qr: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h2v2h-2zM18 14h2v2h-2zM14 18h2v2h-2zM18 18h2v2h-2z',
  user: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4.5 20.5a7.5 7.5 0 0 1 15 0',
  calendar: 'M5 5h14v15H5zM5 10h14M9 3v4M15 3v4',
  check: 'M5 12.5l4.5 4.5L19 7.5',
  backspace: 'M9 5h11v14H9l-6-7zM12.5 9.5l5 5M17.5 9.5l-5 5',
  alert: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7.5v5.5M12 16.5v.01',
  eyeoff: 'M3 3l18 18M10.6 6.1A9.8 9.8 0 0 1 12 6c5 0 9 6 9 6a16 16 0 0 1-3 3.5M6.3 7.8C4.2 9.4 3 12 3 12s4 6 9 6a9.5 9.5 0 0 0 4-.9M9.9 10a3 3 0 0 0 4.1 4.2',
  swap: 'M7 4 3 8l4 4M3 8h14M17 20l4-4-4-4M21 16H7',
  back: 'M15 6l-6 6 6 6',
} as const

export type IconName = keyof typeof PATHS
</script>

<template>
  <svg
    viewBox="0 0 24 24"
    :fill="props.filled ? 'currentColor' : 'none'"
    stroke="currentColor"
    stroke-width="1.8"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
  >
    <path :d="d" />
  </svg>
</template>
