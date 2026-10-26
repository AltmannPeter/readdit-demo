import { PHONES, findPhone, type PhoneDef } from '~/wallet/holder'

/** The demo phone on screen. It stays chosen across dialogs until swapped; Swap phone hands over
 *  to the next phone in PHONES' order (teen, adult, teen's BBS phone, then the teen's again). */
export function usePhone() {
  const id = useState<PhoneDef['id']>('phone', () => 'teen')
  const phone = computed(() => findPhone(id.value))
  const other = computed(() => PHONES[(PHONES.findIndex((p) => p.id === id.value) + 1) % PHONES.length]!)
  function swap() {
    id.value = other.value.id
  }
  return { id, phone, other, swap }
}
