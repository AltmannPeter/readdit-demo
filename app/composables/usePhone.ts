import { PHONES, findPhone, type PhoneDef } from '~/wallet/holder'

/** The demo phone on screen. It stays chosen across dialogs until swapped. */
export function usePhone() {
  const id = useState<PhoneDef['id']>('phone', () => 'teen')
  const phone = computed(() => findPhone(id.value))
  const other = computed(() => PHONES.find((p) => p.id !== id.value) ?? PHONES[0]!)
  function swap() {
    id.value = other.value.id
  }
  return { id, phone, other, swap }
}
