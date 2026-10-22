<script setup lang="ts">
// Read-only, syntax-highlighted JSON for the developer console.
const props = withDefaults(defineProps<{ value: unknown; maxHeight?: string; copyable?: boolean }>(), {
  maxHeight: 'none',
  copyable: true,
})

const text = computed(() => (typeof props.value === 'string' ? props.value : JSON.stringify(props.value, null, 2)))

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

const html = computed(() =>
  esc(text.value).replace(
    /("(\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
    (m) => {
      let cls = 'n'
      if (m.startsWith('"')) cls = m.trimEnd().endsWith(':') ? 'k' : 's'
      else if (m === 'true' || m === 'false') cls = 'b'
      else if (m === 'null') cls = 'z'
      return `<span class="${cls}">${m}</span>`
    },
  ),
)

const copied = ref(false)
async function copy() {
  try {
    await navigator.clipboard.writeText(text.value)
    copied.value = true
    setTimeout(() => (copied.value = false), 1200)
  } catch {
    /* the clipboard may be blocked */
  }
}
</script>

<template>
  <div class="json">
    <button v-if="copyable" class="copy" type="button" @click="copy">{{ copied ? 'Copied' : 'Copy' }}</button>
    <!-- eslint-disable-next-line vue/no-v-html -->
    <pre :style="{ maxHeight }" v-html="html" />
  </div>
</template>

<style scoped>
.json { position: relative; }
pre {
  margin: 0;
  padding: 12px 14px;
  font-size: 12px;
  line-height: 1.6;
  color: var(--ink-2);
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 8px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-all;
}
pre :deep(.k) { color: #1d4ed8; }
pre :deep(.s) { color: #047857; }
pre :deep(.n) { color: #b45309; }
pre :deep(.b) { color: #7c3aed; }
pre :deep(.z) { color: var(--faint); }
.copy {
  position: absolute;
  top: 6px;
  right: 6px;
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 6px;
  border: 1px solid var(--line);
  background: var(--bg);
  color: var(--muted);
  opacity: 0;
  transition: opacity 0.15s;
}
.json:hover .copy,
.copy:focus-visible { opacity: 1; }
</style>
