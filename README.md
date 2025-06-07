bip39-cli
=========

A command-line tool for BIP39 mnemonic operations built on the rust-bitcoin ecosystem.

This tool provides a complete implementation of [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) operations using the trusted `rust-bitcoin/rust-bip39` library.

## Features

- Generate mnemonics with 12, 15, 18, 21, or 24 words
- Validate BIP39 mnemonic phrases
- Convert mnemonics to seeds with optional passphrase support
- Generate mnemonics from provided entropy
- Extract entropy from existing mnemonics
- Support for all 10 BIP39 standard languages
- Shell completion generation
- Single binary for airgapped systems
- Built with rust-bitcoin ecosystem standards

## Installation

### From Crates.io (when published)

```bash
cargo install bip39-cli
```

### From Source

```bash
git clone https://github.com/robcohen/bip39-cli.git
cd bip39-cli
cargo build --release
# Binary will be at target/release/bip39
```

## Usage

### Generate a New Mnemonic

```bash
# Generate 24-word mnemonic (default)
bip39 generate

# Generate 12-word mnemonic
bip39 generate --words 12

# Generate with entropy and seed display
bip39 generate --show-entropy --show-seed

# Generate in Japanese
bip39 generate --language japanese
```

### Validate a Mnemonic

```bash
bip39 validate "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

### Convert Mnemonic to Seed

```bash
bip39 seed "your mnemonic phrase here"

# With passphrase
bip39 seed "your mnemonic phrase here" --passphrase "optional passphrase"
```

### Generate from Entropy

```bash
# From hex entropy (32 bytes = 64 hex chars for 24 words)
bip39 from-entropy "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
```

### Extract Entropy from Mnemonic

```bash
bip39 entropy "your mnemonic phrase here"
```

## Supported Languages

- English (default)
- Chinese Simplified
- Chinese Traditional  
- Czech
- French
- Italian
- Japanese
- Korean
- Portuguese
- Spanish

## Word Counts and Entropy

| Words | Entropy Bits | Entropy Bytes | Hex Length |
|-------|--------------|---------------|------------|
| 12    | 128          | 16            | 32         |
| 15    | 160          | 20            | 40         |
| 18    | 192          | 24            | 48         |
| 21    | 224          | 28            | 56         |
| 24    | 256          | 32            | 64         |

## Security Considerations

- This tool uses `OsRng` for cryptographically secure random number generation
- For maximum security, compile and run on an airgapped system
- Verify the authenticity of this tool before use in production
- Never share your mnemonic phrases - they provide full access to your funds

## Building for Airgapped Systems

```bash
# Build optimized release binary
cargo build --release --target x86_64-unknown-linux-musl

# The resulting binary has no dependencies and can be transferred to airgapped systems
```

## Contributing

This tool is designed to be minimal and auditable. Contributions should maintain these principles:

1. Keep dependencies minimal and well-audited
2. Maintain clean, readable code
3. Include comprehensive tests
4. Follow security best practices

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.

## Acknowledgments

Built on the excellent `rust-bitcoin/rust-bip39` library maintained by the Rust Bitcoin community.