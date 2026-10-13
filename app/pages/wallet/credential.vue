<script setup lang="ts">
import type { CredentialView } from '~/wallet/holder'
import { loadCredential, nymCard } from '~/wallet/holder'

// The credential's details in a separate window, opened from the phone's "Dataset" button.
// Everything shown is decoded from the credential the wallet holds (app/wallet/holder.ts).
definePageMeta({ layout: false })
useHead({ title: 'Age and pseudonym · SIROS ID' })

const c = ref<CredentialView | null>(null)
const error = ref(false)
onMounted(async () => {
  try {
    c.value = await loadCredential()
  } catch {
    error.value = true
  }
})

const fmtDate = (s?: string) =>
  s ? new Date(s.length === 10 ? `${s}T00:00:00Z` : s).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' }) : ''
const valid = computed(() => {
  if (!c.value) return false
  const now = Date.now()
  return now >= Date.parse(c.value.validity.validFrom) && now < Date.parse(c.value.validity.validUntil)
})
</script>

<template>
  <div class="sid-font min-h-screen bg-white text-sid-gray-900">
    <WalletAppHeader />
    <div class="mx-auto max-w-xl px-6 py-6">
      <p v-if="error" class="rounded-lg border border-sid-gray-400 p-4 text-sm">The credential could not be read.</p>

      <template v-else-if="c">
        <WalletH1 :heading="c.title" :hr="false" />
        <div class="mt-2 max-w-sm overflow-hidden rounded-xl shadow-md">
          <WalletCard :credential="nymCard(c)" />
        </div>
        <div class="mt-3 flex items-center gap-2 text-sm">
          <span class="size-2 rounded-full" :class="valid ? 'bg-sid-green' : 'bg-sid-red'" />
          {{ valid ? 'Valid' : 'Not valid' }} until {{ fmtDate(c.validity.validUntil) }}
        </div>

        <section class="mt-6">
          <h2 class="text-lg font-bold">What this credential contains</h2>
          <dl class="mt-2 divide-y divide-sid-gray-400 rounded-lg border border-sid-gray-400">
            <div class="p-4">
              <dt class="text-xs text-sid-gray-700">Date of birth</dt>
              <dd class="mt-0.5 font-semibold">{{ fmtDate(c.attributes.birth_date) }}</dd>
              <dd class="mt-1 text-xs leading-snug text-sid-gray-700">Used to prove an age range. Never sent to a site.</dd>
            </div>
            <div class="p-4">
              <dt class="text-xs text-sid-gray-700">Seed commitment</dt>
              <dd class="mt-0.5 font-mono text-xs break-all">{{ c.attributes.ssc }}</dd>
              <dd class="mt-1 text-xs leading-snug text-sid-gray-700">
                A fingerprint of a secret seed known to you and the issuer. Each site's pseudonym is computed from the seed.
                Sites only receive the pseudonym and a proof that it was computed correctly.
              </dd>
            </div>
            <div class="p-4">
              <dt class="text-xs text-sid-gray-700">Private seed commitment</dt>
              <dd class="mt-0.5 text-sm">{{ c.attributes.psc ? c.attributes.psc : 'Not included' }}</dd>
              <dd class="mt-1 text-xs leading-snug text-sid-gray-700">Optional. A seed only you know, for pseudonyms the issuer cannot trace.</dd>
            </div>
          </dl>
        </section>

        <section class="mt-6">
          <h2 class="text-lg font-bold">What a site receives</h2>
          <div class="mt-2 rounded-lg bg-sid-gray-300 p-4 text-sm leading-relaxed">
            A pseudonym computed for that site, the same each time you use this credential there, and, if the site asks, proof
            that you are in an age range. None of the values above are sent.
          </div>
        </section>

        <section class="mt-6">
          <h2 class="text-lg font-bold">Issuer and protection</h2>
          <dl class="mt-2 divide-y divide-sid-gray-400 rounded-lg border border-sid-gray-400 text-sm">
            <div class="flex justify-between gap-4 p-4">
              <dt class="text-sid-gray-700">Issued by</dt>
              <dd class="text-right">{{ c.issuer.name }}<span v-if="c.issuer.country"> ({{ c.issuer.country }})</span></dd>
            </div>
            <div class="flex justify-between gap-4 p-4">
              <dt class="text-sid-gray-700">Issued</dt>
              <dd>{{ fmtDate(c.validity.signed) }}</dd>
            </div>
            <div class="flex justify-between gap-4 p-4">
              <dt class="text-sid-gray-700">Issuer signature</dt>
              <dd class="text-right">{{ c.mso.signatureAlgorithm }}<br /><span class="text-xs text-sid-gray-700">{{ c.issuer.documentSigner }}</span></dd>
            </div>
            <div class="flex justify-between gap-4 p-4">
              <dt class="text-sid-gray-700">Attribute digests</dt>
              <dd>{{ c.mso.digestAlgorithm }}</dd>
            </div>
            <div class="p-4">
              <div class="flex justify-between gap-4">
                <dt class="text-sid-gray-700">Device key</dt>
                <dd>{{ c.deviceKey.kty }} {{ c.deviceKey.crv }}</dd>
              </div>
              <dd class="mt-1 font-mono text-xs break-all text-sid-gray-700">{{ c.deviceKey.jwkThumbprint }}</dd>
              <dd class="mt-1 text-xs text-sid-gray-700">{{ c.deviceKey.protection }}</dd>
            </div>
          </dl>
        </section>

        <section class="mt-6">
          <h2 class="text-lg font-bold">Format</h2>
          <dl class="mt-2 divide-y divide-sid-gray-400 rounded-lg border border-sid-gray-400 text-sm">
            <div class="flex justify-between gap-4 p-4">
              <dt class="text-sid-gray-700">Document type</dt>
              <dd class="font-mono text-xs">{{ c.docType }}</dd>
            </div>
            <div class="flex justify-between gap-4 p-4">
              <dt class="text-sid-gray-700">Encoding</dt>
              <dd class="text-right">{{ c.encoding }}<span v-if="c.compactProfile">, compact profile</span></dd>
            </div>
            <div class="flex justify-between gap-4 p-4">
              <dt class="text-sid-gray-700">Data elements</dt>
              <dd class="font-mono text-xs">{{ c.elements.map((e) => `${e.digestID}: ${e.id}`).join(', ') }}</dd>
            </div>
            <div class="flex justify-between gap-4 p-4">
              <dt class="text-sid-gray-700">Size</dt>
              <dd>{{ c.sizes.issuerSigned }} bytes</dd>
            </div>
          </dl>
        </section>
      </template>
    </div>
  </div>
</template>
