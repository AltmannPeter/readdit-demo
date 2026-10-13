const OPEN_WIDTH = '22rem'
const CLOSED_WIDTH = '2.75rem'
const STORAGE_KEY = 'readdit-guide-open'

/** The guide panel docked at the right edge: open or collapsed, and the width the site leaves for it. */
export function useGuidePanel() {
  const open = useState('guide-open', () => true)
  const width = computed(() => (open.value ? OPEN_WIDTH : CLOSED_WIDTH))

  function toggle() {
    open.value = !open.value
    try {
      localStorage.setItem(STORAGE_KEY, open.value ? '1' : '0')
    } catch {
      /* storage unavailable: the choice lasts for this page */
    }
  }

  /** Restores the presenter's last choice; call once the page is mounted. */
  function restore() {
    try {
      const saved = localStorage.getItem(STORAGE_KEY)
      if (saved != null) open.value = saved === '1'
    } catch {
      /* storage unavailable */
    }
  }

  return { open, width, toggle, restore }
}
