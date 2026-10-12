// Starts the stub prover (:8081) and stub verifier (:8082) together.
// Ctrl+C stops both. Works on macOS, Linux and Windows.
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const children = [
  { name: 'prover', port: 8081 },
  { name: 'verifier', port: 8082 },
].map(({ name, port }) =>
  spawn(process.execPath, [fileURLToPath(new URL(`./${name}/server.mjs`, import.meta.url))], {
    stdio: 'inherit',
    env: { ...process.env, PORT: String(port) },
  }),
)

const stop = (code = 0) => {
  for (const c of children) if (c.exitCode === null) c.kill()
  process.exit(code)
}
process.on('SIGINT', () => stop(0))
process.on('SIGTERM', () => stop(0))
for (const c of children) c.on('exit', (code) => stop(code ?? 1))
