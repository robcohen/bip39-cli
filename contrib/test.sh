#!/bin/sh

set -ex

cargo --version
rustc --version

echo "********* Testing default *************"
cargo test --verbose

echo "********* Testing release build *************"
cargo build --release --verbose

echo "********* Running clippy *************"
cargo clippy --all-targets --all-features -- -D warnings

echo "********* Checking formatting *************"
cargo fmt --all -- --check

echo "********* Testing binary functionality *************"
# Test basic commands work
./target/release/bip39 generate --words 12
./target/release/bip39 validate "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"