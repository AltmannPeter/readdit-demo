export type BackendMode = 'services' | 'offline'

interface ModeState {
  mode: BackendMode
  phoneFactor: number
}

const g = globalThis as unknown as { __readditBackend?: ModeState }

/** Which backend the site uses. Starts from runtime config; /mod can switch it. Not cleared by Reset demo. */
export function backendMode(): ModeState {
  if (!g.__readditBackend) {
    const cfg = useRuntimeConfig()
    g.__readditBackend = {
      mode: cfg.backendMode === 'offline' ? 'offline' : 'services',
      phoneFactor: clampFactor(Number(cfg.offlinePhoneFactor)),
    }
  }
  return g.__readditBackend
}

export function clampFactor(n: number): number {
  return Number.isFinite(n) ? Math.min(5, Math.max(1, Math.round(n))) : 2
}
