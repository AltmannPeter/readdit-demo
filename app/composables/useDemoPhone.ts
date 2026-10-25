const STORAGE_KEY = 'community-demo-phone'

/** Whether the site dialog shows the demo phone beside the QR code. Hidden at first: the main flow
 *  scans the code with a real phone. The presenter's choice is kept in this browser. */
export function useDemoPhone() {
  const shown = useState('demo-phone-shown', () => false)

  function toggle() {
    shown.value = !shown.value
    try {
      localStorage.setItem(STORAGE_KEY, shown.value ? '1' : '0')
    } catch {
      /* storage unavailable: the choice lasts for this page */
    }
  }

  /** Restores the presenter's last choice; call once the page is mounted. */
  function restore() {
    try {
      const saved = localStorage.getItem(STORAGE_KEY)
      if (saved != null) shown.value = saved === '1'
    } catch {
      /* storage unavailable */
    }
  }

  return { shown, toggle, restore }
}
