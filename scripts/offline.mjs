// Runs the site with the built-in offline backend: no prover/verifier services, no network.
//   node scripts/offline.mjs dev     development server (npm run dev:offline)
//   node scripts/offline.mjs start   built site from .output (npm run build first; npm run start:offline)
import { spawn } from 'node:child_process'

const mode = process.argv[2] === 'start' ? 'start' : 'dev'
const [cmd, args] = mode === 'start' ? [process.execPath, ['.output/server/index.mjs']] : ['npx', ['nuxt', 'dev']]
const child = spawn(cmd, args, {
  stdio: 'inherit',
  shell: mode === 'dev' && process.platform === 'win32',
  env: { ...process.env, NUXT_BACKEND_MODE: 'offline' },
})
child.on('exit', (code) => process.exit(code ?? 0))
