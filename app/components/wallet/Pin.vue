<script setup lang="ts">
// Unlocking the wallet before it shares. The SIROS ID wallet unlocks with passkeys; this demo
// keeps a 6-digit PIN screen for the unlock, and any 6 digits unlock it. Laid out like the
// wallet's PIN popup (src/components/Popups/PinInput.jsx: lock icon and title, divider, italic
// description, digit boxes, Cancel and Submit), with the phone's number pad below.
const props = defineProps<{ verifierName: string }>()
const emit = defineEmits<{ done: [pin: string]; cancel: [] }>()
const LENGTH = 6
const pin = ref('')
let submitted = false

function press(d: string) {
  if (submitted || pin.value.length >= LENGTH) return
  pin.value += d
}
function erase() {
  if (submitted) return
  pin.value = pin.value.slice(0, -1)
}
function submit() {
  if (submitted || pin.value.length !== LENGTH) return
  submitted = true
  emit('done', pin.value)
}

function onKey(e: KeyboardEvent) {
  if (/^[0-9]$/.test(e.key)) press(e.key)
  else if (e.key === 'Backspace') erase()
  else if (e.key === 'Enter') submit()
}
onMounted(() => window.addEventListener('keydown', onKey))
onBeforeUnmount(() => window.removeEventListener('keydown', onKey))

const keys = ['1', '2', '3', '4', '5', '6', '7', '8', '9']
</script>

<template>
  <div class="flex h-full flex-col bg-white">
    <WalletAppHeader />
    <div class="flex min-h-0 flex-1 flex-col px-6 pt-6">
      <h2 class="mb-2 flex items-center text-lg font-bold text-sid-gray-900">
        <WalletSirosIcon name="lock" class="mr-1 size-5" />
        Enter the Pin
      </h2>
      <hr class="mb-2 border-t border-sid-gray-400" />
      <p class="text-sid-gray-800 italic">Enter your wallet PIN to share with {{ props.verifierName }}.</p>
      <div class="mt-2 flex justify-center" aria-label="PIN">
        <span
          v-for="i in LENGTH"
          :key="i"
          class="mx-0.5 my-2 flex h-10 w-9 items-center justify-center rounded-md border border-sid-gray-400 bg-sid-gray-200 text-lg text-sid-gray-900"
        >{{ i <= pin.length ? '•' : '' }}</span>
      </div>
      <div class="flex justify-end gap-2 pt-4">
        <WalletButton @click="emit('cancel')">Cancel</WalletButton>
        <WalletButton variant="primary" :disabled="pin.length !== LENGTH" @click="submit">Submit</WalletButton>
      </div>
    </div>
    <!-- the phone's number pad -->
    <div class="grid shrink-0 grid-cols-3 gap-1.5 bg-sid-gray-300 px-1.5 pt-1.5 pb-8">
      <button v-for="k in keys" :key="k" class="h-11 rounded-md bg-white text-xl font-medium text-sid-gray-900 shadow-xs active:bg-sid-gray-400" @click="press(k)">{{ k }}</button>
      <span />
      <button class="h-11 rounded-md bg-white text-xl font-medium text-sid-gray-900 shadow-xs active:bg-sid-gray-400" @click="press('0')">0</button>
      <button class="flex h-11 items-center justify-center text-sid-gray-900" aria-label="Delete" @click="erase">
        <WalletSirosIcon name="delete" class="size-6" />
      </button>
    </div>
  </div>
</template>
