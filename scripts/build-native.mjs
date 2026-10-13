// Builds the Vega Node addon (native/vega/node, Rust) and copies it to native/vega/readdit-vega.node,
// where the site's server loads it (server/utils/services.ts). Needs Rust (https://rustup.rs).
// Usage: npm run build:native
import { spawnSync } from 'node:child_process'
import { copyFileSync, existsSync, renameSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

const root = fileURLToPath(new URL('../native/vega/', import.meta.url))
const env = { ...process.env, CARGO_BUILD_JOBS: process.env.CARGO_BUILD_JOBS ?? '4' }
const build = spawnSync('cargo', ['build', '--release', '--locked', '-p', 'readdit-vega-node'], { cwd: root, stdio: 'inherit', env })
if (build.error) {
  console.error(`build:native: cannot run cargo (${build.error.message}). Install Rust from https://rustup.rs`)
  process.exit(1)
}
if (build.status !== 0) process.exit(build.status ?? 1)

const names = { linux: 'libreaddit_vega_node.so', darwin: 'libreaddit_vega_node.dylib', win32: 'readdit_vega_node.dll' }
const name = names[process.platform]
if (!name) {
  console.error(`build:native: no addon file name for platform ${process.platform}`)
  process.exit(1)
}
const target = process.env.CARGO_TARGET_DIR ?? join(root, 'target')
const built = join(target, 'release', name)
if (!existsSync(built)) {
  console.error(`build:native: cargo succeeded but ${built} is missing`)
  process.exit(1)
}
// Copy, then rename over the old addon: a running site keeps the old file mapped, untouched.
const out = join(root, 'readdit-vega.node')
copyFileSync(built, `${out}.tmp`)
try {
  renameSync(`${out}.tmp`, out)
} catch (e) {
  console.error(`build:native: cannot replace ${out} (${e.message}). Stop the site and run it again.`)
  process.exit(1)
}
console.log(`build:native: ${out} (restart the site to load it)`)
