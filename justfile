set shell := ["bash", "-c"]

check:
    cargo check --all-targets

fmt:
    cargo fmt --check

clippy:
    cargo clippy --all-targets -- -D warnings

test:
    cargo test --all-targets

ci: fmt check clippy test
