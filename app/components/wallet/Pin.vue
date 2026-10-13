<script setup lang="ts">
// Unlocking the device key with the wallet PIN. The SIROS ID wallet unlocks with passkeys; this
// demo keeps a 6-digit PIN as its second factor, laid out like the wallet's PIN popup
// (src/components/Popups/PinInput.jsx), with the phone's number pad below.
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
  <div class="flex h-full flex-col bg-white">
    <WalletAppHeader />
    <div class="flex min-h-0 flex-1 flex-col px-6 pt-6">
      <h2 class="mb-2 flex items-center text-lg font-bold text-sid-gray-900">
        <WalletSirosIcon name="lock" class="mr-2 size-5" />
        Enter your PIN
      </h2>
      <hr class="mb-2 border-t border-sid-gray-400" />
      <p class="text-sm text-sid-gray-800 italic">Your PIN unlocks the device key to share with {{ props.verifierName }}.</p>
      <div class="mt-4 flex justify-center" aria-label="PIN">
        <span
          v-for="i in LENGTH"
          :key="i"
          class="mx-0.5 flex h-11 w-9 items-center justify-center rounded-md border border-sid-gray-400 bg-sid-gray-200 text-lg text-sid-gray-900"
        >{{ i <= pin.length ? '•' : '' }}</span>
      </div>
      <p v-if="props.error" class="mt-3 text-center text-sm text-sid-red">{{ props.error }}</p>
      <div class="mt-4 flex justify-start">
        <WalletButton @click="emit('cancel')">Cancel</WalletButton>
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
