default:
    @just --list

build:
    cargo build --workspace

test:
    cargo test --workspace

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --workspace --all-targets -- -D warnings

check: fmt-check lint test

probe *args:
    cargo run --bin scd-rs-probe -- {{args}}

run *args:
    cargo run --bin scd-rs -- {{args}}

clean:
    cargo clean
