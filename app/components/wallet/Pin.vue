<script setup lang="ts">
const props = defineProps<{ verifierName: string; error?: string }>()
const emit = defineEmits<{ done: [pin: string]; cancel: [] }>()
const LENGTH = 6
const pin = ref('')
let finished = false

function press(d: string) {
  if (finished || pin.value.length >= LENGTH) return
  pin.value += d
  if (pin.value.length === LENGTH) {
    finished = true
    setTimeout(() => emit('done', pin.value), 300)
  }
}
const erase = () => !finished && (pin.value = pin.value.slice(0, -1))

function onKey(e: KeyboardEvent) {
  if (/^[0-9]$/.test(e.key)) press(e.key)
  else if (e.key === 'Backspace') erase()
}
onMounted(() => window.addEventListener('keydown', onKey))
onBeforeUnmount(() => window.removeEventListener('keydown', onKey))

const keys = ['1', '2', '3', '4', '5', '6', '7', '8', '9']
</script>

<template>
  <div class="flex h-full flex-col items-center px-6 pb-9">
    <span class="mt-8 flex size-11 items-center justify-center rounded-full bg-w-soft text-w-primary">
      <AppIcon name="lock" class="size-5" />
    </span>
    <h2 class="mt-3 text-lg font-semibold text-w-ink">Enter your PIN</h2>
    <p class="mt-1 text-center text-xs" :class="props.error ? 'font-semibold text-adult' : 'text-w-muted'">
      {{ props.error || `To share with ${props.verifierName}` }}
    </p>

    <div class="mt-6 flex gap-3" aria-label="PIN">
      <span
        v-for="i in LENGTH"
        :key="i"
        class="size-3 rounded-full border-2 border-w-primary transition-colors"
        :class="i <= pin.length ? 'bg-w-primary' : 'bg-transparent'"
      />
    </div>

    <div class="mt-auto grid w-full grid-cols-3 gap-x-5 gap-y-3">
      <button
        v-for="k in keys"
        :key="k"
        class="mx-auto flex size-[60px] items-center justify-center rounded-full bg-w-surface text-2xl font-medium text-w-ink active:bg-w-soft"
        @click="press(k)"
      >
        {{ k }}
      </button>
      <button class="mx-auto flex size-[60px] items-center justify-center text-sm font-semibold text-w-primary" @click="emit('cancel')">
        Cancel
      </button>
      <button
        class="mx-auto flex size-[60px] items-center justify-center rounded-full bg-w-surface text-2xl font-medium text-w-ink active:bg-w-soft"
        @click="press('0')"
      >
        0
      </button>
      <button class="mx-auto flex size-[60px] items-center justify-center text-w-ink" aria-label="Delete" @click="erase">
        <AppIcon name="backspace" class="size-6" />
      </button>
    </div>
  </div>
</template>
