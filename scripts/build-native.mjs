// Builds the proof backends' Node addons (Rust) and copies each where the site's server loads it
// (server/utils/services.ts):
//   native/vega/node       -> native/vega/readdit-vega.node              (mso_mdoc: Vega)
//   native/longfellow/node -> native/longfellow/readdit-longfellow.node  (mso_mdoc: Longfellow)
//   native/bbs/node        -> native/bbs/readdit-bbs.node                (bbs_cd: BBS committed disclosures)
// Needs Rust (https://rustup.rs). Longfellow's target features (carry-less multiply) are in
// native/longfellow/.cargo/config.toml.
// Usage: npm run build:native [-- vega|longfellow|bbs]   (default: all three)
import { spawnSync } from 'node:child_process'
import { copyFileSync, existsSync, renameSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

const ADDONS = {
  vega: { dir: '../native/vega/', crate: 'readdit-vega-node', lib: 'readdit_vega_node', out: 'readdit-vega.node' },
  longfellow: { dir: '../native/longfellow/', crate: 'readdit-longfellow-node', lib: 'readdit_longfellow_node', out: 'readdit-longfellow.node' },
  bbs: { dir: '../native/bbs/', crate: 'readdit-bbs-node', lib: 'readdit_bbs_node', out: 'readdit-bbs.node' },
}
const only = process.argv[2]
if (only && !ADDONS[only]) {
  console.error(`build:native: unknown addon ${only}; use one of ${Object.keys(ADDONS).join(', ')}`)
  process.exit(1)
}
const env = { ...process.env, CARGO_BUILD_JOBS: process.env.CARGO_BUILD_JOBS ?? '4' }

function build(name, a) {
  const root = fileURLToPath(new URL(a.dir, import.meta.url))
  const run = spawnSync('cargo', ['build', '--release', '--locked', '-p', a.crate], { cwd: root, stdio: 'inherit', env })
  if (run.error) {
    console.error(`build:native: cannot run cargo (${run.error.message}). Install Rust from https://rustup.rs`)
    process.exit(1)
  }
  if (run.status !== 0) return false
  const file = { linux: `lib${a.lib}.so`, darwin: `lib${a.lib}.dylib`, win32: `${a.lib}.dll` }[process.platform]
  if (!file) {
    console.error(`build:native: no addon file name for platform ${process.platform}`)
    process.exit(1)
  }
  const built = join(process.env.CARGO_TARGET_DIR ?? join(root, 'target'), 'release', file)
  if (!existsSync(built)) {
    console.error(`build:native: cargo succeeded but ${built} is missing`)
    return false
  }
  // Copy, then rename over the old addon: a running site keeps the old file mapped, untouched.
  const out = join(root, a.out)
  copyFileSync(built, `${out}.tmp`)
  try {
    renameSync(`${out}.tmp`, out)
  } catch (e) {
    console.error(`build:native: cannot replace ${out} (${e.message}). Stop the site and run it again.`)
    return false
  }
  console.log(`build:native: ${name}: ${out}`)
  return true
}

const failed = Object.entries(ADDONS)
  .filter(([name]) => !only || name === only)
  .filter(([name, a]) => !build(name, a))
  .map(([name]) => name)
if (failed.length) {
  console.error(`build:native: ${failed.join(', ')} failed. The site starts with the backends that load.`)
  process.exit(1)
}
console.log('build:native: done (restart the site to load the addons)')
