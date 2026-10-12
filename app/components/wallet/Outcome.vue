<script setup lang="ts">
const props = defineProps<{ kind: 'done' | 'declined' | 'error'; verifierName?: string; text?: string }>()
defineEmits<{ close: [] }>()

const title = computed(() =>
  props.kind === 'done' ? `Shared with ${props.verifierName}` : props.kind === 'declined' ? 'Nothing was shared' : 'Something went wrong',
)
const body = computed(
  () => props.text ?? (props.kind === 'done' ? 'You can go back to the website.' : props.kind === 'declined' ? 'You cancelled the request.' : ''),
)
</script>

<template>
  <div class="flex h-full flex-col px-4 pb-8">
    <div class="flex flex-1 flex-col items-center justify-center px-4 text-center">
      <span
        class="flex size-16 items-center justify-center rounded-full"
        :class="props.kind === 'done' ? 'bg-w-primary text-white' : 'bg-w-soft text-w-primary'"
      >
        <AppIcon :name="props.kind === 'done' ? 'check' : props.kind === 'declined' ? 'close' : 'alert'" class="size-8" />
      </span>
      <h2 class="mt-5 text-lg font-semibold text-w-ink">{{ title }}</h2>
      <p v-if="body" class="mt-1 text-sm text-w-muted">{{ body }}</p>
    </div>
    <button class="h-12 w-full rounded-2xl bg-w-primary text-[15px] font-semibold text-white active:bg-w-strong" @click="$emit('close')">
      Done
    </button>
  </div>
</template>
