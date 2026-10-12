<script setup lang="ts">
import type { CredentialView } from '~/wallet/holder'

definePageMeta({ layout: false })
useHead({ title: 'Age and pseudonym · EUDI Wallet App' })

const { data: c, error } = await useFetch<CredentialView>('/api/wallet/credential')

const fmtDate = (s?: string) =>
  s ? new Date(s.length === 10 ? `${s}T00:00:00Z` : s).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' }) : ''
const valid = computed(() => {
  if (!c.value) return false
  const now = Date.now()
  return now >= Date.parse(c.value.validity.validFrom) && now <= Date.parse(c.value.validity.validUntil)
})
</script>

<template>
  <div class="min-h-screen bg-w-bg text-w-ink">
    <div class="mx-auto max-w-xl px-6 py-8">
      <p class="text-[11px] font-semibold tracking-wider text-w-muted uppercase">EUDI Wallet App</p>

      <p v-if="error" class="mt-6 rounded-2xl bg-w-surface p-4 text-sm">The wallet service is not available.</p>

      <template v-else-if="c">
        <div class="mt-3 max-w-sm">
          <WalletCredentialCard :credential="{ title: c.title, issuer: c.issuer.name, subtitle: 'Pseudonyms and age checks' }" />
        </div>
        <div class="mt-3 flex items-center gap-2 text-sm">
          <span class="size-2 rounded-full" :class="valid ? 'bg-emerald-500' : 'bg-adult'" />
          {{ valid ? 'Valid' : 'Not valid' }} until {{ fmtDate(c.validity.validUntil) }}
        </div>

        <section class="mt-6">
          <h2 class="px-1 text-sm font-semibold">What this credential contains</h2>
          <dl class="mt-2 divide-y divide-w-line rounded-2xl bg-w-surface">
            <div class="p-4">
              <dt class="text-xs text-w-muted">Date of birth</dt>
              <dd class="mt-0.5 font-semibold">{{ fmtDate(c.attributes.birth_date) }}</dd>
              <dd class="mt-1 text-xs leading-snug text-w-muted">Used to prove an age range. Never sent to a site.</dd>
            </div>
            <div class="p-4">
              <dt class="text-xs text-w-muted">Seed commitment</dt>
              <dd class="mt-0.5 font-mono text-xs break-all">{{ c.attributes.ssc }}</dd>
              <dd class="mt-1 text-xs leading-snug text-w-muted">
                A fingerprint of a secret seed known to you and the issuer. Each site's pseudonym is computed from the seed.
                Sites only receive the pseudonym and a proof that it was computed correctly.
              </dd>
            </div>
            <div class="p-4">
              <dt class="text-xs text-w-muted">Private seed commitment</dt>
              <dd class="mt-0.5 text-sm">{{ c.attributes.psc ? c.attributes.psc : 'Not included' }}</dd>
              <dd class="mt-1 text-xs leading-snug text-w-muted">Optional. A seed only you know, for pseudonyms the issuer cannot trace.</dd>
            </div>
          </dl>
        </section>

        <section class="mt-6">
          <h2 class="px-1 text-sm font-semibold">What a site receives</h2>
          <div class="mt-2 rounded-2xl bg-w-soft/70 p-4 text-sm leading-relaxed">
            A pseudonym that only works on that site, and, if the site asks, a yes or no answer to an age range. None of the
            values above are sent.
          </div>
        </section>

        <section class="mt-6">
          <h2 class="px-1 text-sm font-semibold">Issuer and protection</h2>
          <dl class="mt-2 divide-y divide-w-line rounded-2xl bg-w-surface text-sm">
            <div class="flex justify-between gap-4 p-4">
              <dt class="text-w-muted">Issued by</dt>
              <dd class="text-right">{{ c.issuer.name }}<span v-if="c.issuer.country"> ({{ c.issuer.country }})</span></dd>
            </div>
            <div class="flex justify-between gap-4 p-4">
              <dt class="text-w-muted">Issued</dt>
              <dd>{{ fmtDate(c.validity.signed) }}</dd>
            </div>
            <div class="flex justify-between gap-4 p-4">
              <dt class="text-w-muted">Issuer signature</dt>
              <dd class="text-right">{{ c.mso.signatureAlgorithm }}<br /><span class="text-xs text-w-muted">{{ c.issuer.documentSigner }}</span></dd>
            </div>
            <div class="flex justify-between gap-4 p-4">
              <dt class="text-w-muted">Attribute digests</dt>
              <dd>{{ c.mso.digestAlgorithm }}</dd>
            </div>
            <div class="p-4">
              <div class="flex justify-between gap-4">
                <dt class="text-w-muted">Device key</dt>
                <dd>{{ c.deviceKey.kty }} {{ c.deviceKey.crv }}</dd>
              </div>
              <dd class="mt-1 font-mono text-xs break-all text-w-muted">{{ c.deviceKey.jwkThumbprint }}</dd>
              <dd v-if="c.deviceKey.protection" class="mt-1 text-xs text-w-muted">{{ c.deviceKey.protection }}</dd>
            </div>
          </dl>
        </section>

        <section class="mt-6">
          <h2 class="px-1 text-sm font-semibold">Format</h2>
          <dl class="mt-2 divide-y divide-w-line rounded-2xl bg-w-surface text-sm">
            <div class="flex justify-between gap-4 p-4">
              <dt class="text-w-muted">Document type</dt>
              <dd class="font-mono text-xs">{{ c.docType }}</dd>
            </div>
            <div class="flex justify-between gap-4 p-4">
              <dt class="text-w-muted">Encoding</dt>
              <dd>{{ c.encoding }}<span v-if="c.compactProfile">, compact profile</span></dd>
            </div>
          </dl>
        </section>
      </template>
    </div>
  </div>
</template>
