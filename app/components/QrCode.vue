<script setup lang="ts">
import QRCode from 'qrcode'

const props = withDefaults(defineProps<{ value: string; dark?: string; light?: string }>(), {
  dark: '#1a1d21',
  light: '#ffffff',
})
const svg = ref('')

watchEffect(async () => {
  svg.value = await QRCode.toString(props.value, {
    type: 'svg',
    margin: 0,
    errorCorrectionLevel: 'M',
    color: { dark: props.dark, light: props.light },
  })
})
</script>

<template>
  <!-- eslint-disable-next-line vue/no-v-html -->
  <div class="[&>svg]:block [&>svg]:size-full" role="img" aria-label="QR code" v-html="svg" />
</template>
