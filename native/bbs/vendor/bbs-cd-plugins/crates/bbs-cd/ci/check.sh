#!/usr/bin/env bash
# Run the same complete checks locally and in GitHub Actions.
set -euo pipefail
cd "$(dirname "$0")/.."

rust_toolchain="${1:-stable}"
case "$rust_toolchain" in
  ''|*[!a-zA-Z0-9._-]*) printf 'Invalid Rust toolchain: %s\n' "$rust_toolchain" >&2; exit 2 ;;
esac
report_dir="$PWD/target/conformance/$rust_toolchain"
mkdir -p "$report_dir"
# Remove only this command's previous reports, so a failed run cannot publish stale results.
rm -f "$report_dir/profile.json" "$report_dir/bbs-sha256.json" "$report_dir/bbs-shake256.json"

run_checks() {
  cargo "+$rust_toolchain" fmt --all -- --check
  cargo "+$rust_toolchain" clippy --locked --all-targets -- -D warnings
  BBS_REPORT_DIR="$report_dir" BBS_PROFILE_REPORT="$report_dir/profile.json" \
    cargo "+$rust_toolchain" test --locked -- --nocapture
  for report in profile.json bbs-sha256.json bbs-shake256.json; do
    if [[ ! -s "$report_dir/$report" ]]; then
      printf 'Required conformance report missing: %s\n' "$report" >&2
      return 1
    fi
  done
  printf 'Complete conformance reports: %s\n' "$report_dir"
}
# pipefail preserves a failed check even when tee successfully saves the log.
run_checks 2>&1 | tee "$report_dir/check.log"
