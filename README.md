# bip39-cli

A comprehensive, secure command-line tool for BIP39 mnemonic operations built on the rust-bitcoin ecosystem.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This tool provides a complete, auditable implementation of [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) operations using the trusted `rust-bitcoin/rust-bip39` library, with advanced security features for production use.

## ✨ Features

### Core BIP39 Operations
- **Generate mnemonics** with 12, 15, 18, 21, or 24 words
- **Validate mnemonic phrases** with detailed error reporting and suggestions
- **Convert mnemonics to seeds** with optional passphrase support
- **Generate mnemonics from entropy** (hex input)
- **Extract entropy** from existing mnemonics
- **Multi-language support** for all 10 BIP39 standard languages

### Security Features
- **🔒 Secure mode** with enhanced security checks and warnings
- **🔐 Secure input** for mnemonics and passphrases (hidden from terminal)
- **🔍 Entropy quality analysis** with statistical validation
- **✈️ Air-gap environment detection** and security recommendations
- **💪 Passphrase strength assessment** with detailed feedback
- **🧹 Memory protection** with automatic zeroization of sensitive data

### Quality Assurance
- **✅ Complete BIP39 compliance** verified against all 24 official test vectors
- **🧪 Comprehensive testing** with 39 passing tests (integration, property-based, compliance)
- **🔧 Enhanced error messages** with helpful suggestions and context
- **📱 Shell completion** generation for bash, zsh, fish, and PowerShell

## 🚀 Installation

### From Source

```bash
git clone https://github.com/robcohen/bip39-cli.git
cd bip39-cli
cargo build --release
# Binary will be at target/release/bip39
```

### Build for Air-Gapped Systems

```bash
# Build static binary with no dependencies
cargo build --release --target x86_64-unknown-linux-musl
# Transfer the self-contained binary to your air-gapped system
```

## 📖 Usage

### Basic Operations

#### Generate a New Mnemonic
```bash
# Generate 12-word mnemonic (secure default)
bip39 generate --words 12

# Generate 24-word mnemonic with entropy display
bip39 generate --words 24 --show-entropy

# Generate with seed derivation
bip39 generate --words 12 --show-seed --passphrase "optional passphrase"

# Generate in Japanese
bip39 generate --words 12 --language japanese
```

#### Validate a Mnemonic
```bash
# Basic validation
bip39 validate "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Validate with detailed output
bip39 validate "your mnemonic here" --language english

# Quiet mode (for scripts)
bip39 validate "your mnemonic" --quiet
```

#### Convert Mnemonic to Seed
```bash
# Generate seed
bip39 seed "your mnemonic phrase here"

# With passphrase
bip39 seed "your mnemonic phrase here" --passphrase "optional passphrase"

# Quiet mode (raw output)
bip39 seed "your mnemonic" --quiet
```

#### Entropy Operations
```bash
# Generate mnemonic from entropy (32 bytes = 64 hex chars for 24 words)
bip39 from-entropy "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

# Extract entropy from mnemonic
bip39 entropy "your mnemonic phrase here"
```

### 🔒 Security Features

#### Secure Mode
```bash
# Enable enhanced security mode
bip39 --secure generate --words 12

# Security check and recommendations
bip39 --security-check
```

#### Secure Input (Hidden from Terminal)
```bash
# Use secure input for mnemonic validation
bip39 validate --secure-input

# Use secure passphrase input for seed generation
bip39 generate --show-seed --secure-passphrase
```

#### Entropy Quality Analysis
```bash
# Analyze entropy quality during generation
bip39 generate --analyze-entropy

# In secure mode, low-quality entropy is rejected
bip39 --secure generate --analyze-entropy
```

#### Passphrase Strength Assessment
```bash
# Analyze passphrase strength
bip39 seed "your mnemonic" --analyze-passphrase
```

### 🛠️ Advanced Usage

#### Shell Completion
```bash
# Generate completion for your shell
bip39 --generate bash > ~/.local/share/bash-completion/completions/bip39
bip39 --generate zsh > ~/.zsh/completions/_bip39
bip39 --generate fish > ~/.config/fish/completions/bip39.fish
```

#### Scripting and Automation
```bash
# Quiet mode for scripts (minimal output)
bip39 generate --words 12 --quiet

# Pipe-friendly operations
echo "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" | bip39 validate --quiet && echo "Valid"
```

## 🌍 Supported Languages

All BIP39 standard languages are supported:

- **English** (default)
- **Chinese Simplified** (`chinese-simplified`)
- **Chinese Traditional** (`chinese-traditional`)
- **Czech** (`czech`)
- **French** (`french`)
- **Italian** (`italian`)
- **Japanese** (`japanese`)
- **Korean** (`korean`)
- **Portuguese** (`portuguese`)
- **Spanish** (`spanish`)

## 📊 Word Counts and Entropy

| Words | Entropy Bits | Entropy Bytes | Hex Length | Security Level |
|-------|--------------|---------------|------------|----------------|
| 12    | 128          | 16            | 32         | High           |
| 15    | 160          | 20            | 40         | Very High      |
| 18    | 192          | 24            | 48         | Very High      |
| 21    | 224          | 28            | 56         | Extremely High |
| 24    | 256          | 32            | 64         | Extremely High |

## 🔐 Security Considerations

### Best Practices
- **Use air-gapped systems** for maximum security when handling production mnemonics
- **Verify software integrity** before use in production environments
- **Use secure mode** (`--secure`) for enhanced security checks
- **Enable entropy analysis** (`--analyze-entropy`) to validate randomness quality
- **Use secure input** (`--secure-input`, `--secure-passphrase`) to prevent terminal logging

### Cryptographic Security
- Uses `OsRng` for cryptographically secure random number generation
- Implements automatic memory zeroization for sensitive data
- Provides entropy quality assessment using statistical tests
- Validates air-gap environment security

### Audit Trail
- **39 comprehensive tests** validate correctness and security
- **All 24 official BIP39 test vectors** verified for compliance
- **Property-based testing** ensures algorithmic correctness
- **Zero compilation warnings** with strict linting

## 🧪 Testing and Validation

This tool includes comprehensive testing:

- **BIP39 Compliance**: All 24 official test vectors pass
- **Integration Tests**: 18 CLI functionality tests
- **Property Tests**: 11 algorithmic validation tests
- **Security Tests**: Entropy quality and air-gap detection

Run tests:
```bash
cargo test
```

## 🏗️ Building

### Development Build
```bash
cargo build
```

### Release Build
```bash
cargo build --release
```

### Static Binary (for air-gapped systems)
```bash
# Install musl target
rustup target add x86_64-unknown-linux-musl

# Build static binary
cargo build --release --target x86_64-unknown-linux-musl
```

## 🤝 Contributing

This tool is designed to be minimal, auditable, and secure. Contributions should maintain these principles:

1. **Security first**: All changes must maintain or improve security
2. **Minimal dependencies**: Only well-audited crates from the Rust Bitcoin ecosystem
3. **Comprehensive testing**: All features must include tests
4. **Clear documentation**: Code should be self-documenting
5. **Zero warnings**: Code must compile cleanly with strict lints

### Development Setup
```bash
git clone https://github.com/robcohen/bip39-cli.git
cd bip39-cli
cargo test  # Run all tests
cargo clippy  # Check for linting issues
cargo fmt  # Format code
```

## 📄 License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## 🙏 Acknowledgments

Built on the excellent libraries maintained by the Rust Bitcoin community:
- [`rust-bip39`](https://github.com/rust-bitcoin/rust-bip39) - BIP39 implementation
- [`rust-bitcoin`](https://github.com/rust-bitcoin/rust-bitcoin) - Bitcoin ecosystem

Special thanks to the Bitcoin Core developers and the BIP39 specification authors for their foundational work.

## 🔗 Related Projects

- [BIP39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [Rust Bitcoin](https://github.com/rust-bitcoin/rust-bitcoin)
- [Hardware Wallet Interface](https://github.com/bitcoin-core/HWI)