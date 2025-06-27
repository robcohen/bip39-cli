#!/usr/bin/env bash
#
# Test script for bip39-cli
#

set -ex

# Run cargo fmt check
cargo fmt --all -- --check

# Run clippy with strict lints
cargo clippy --all-targets --all-features -- -D warnings

# Run all tests
cargo test --all-features

# Run benchmarks (compile only)
cargo bench --no-run

echo "All tests passed!"