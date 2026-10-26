.PHONY: fmt check test profile-test ci-check

RUST_TOOLCHAIN ?= stable

fmt:
	cargo fmt --all

check:
	cargo fmt --all -- --check
	cargo clippy --locked --all-targets -- -D warnings

test:
	cargo test --locked

profile-test:
	cargo test --locked --lib profile_vectors::all_profile_fixtures -- --exact --nocapture

ci-check:
	bash ci/check.sh "$(RUST_TOOLCHAIN)"

