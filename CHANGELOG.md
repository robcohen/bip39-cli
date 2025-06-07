CHANGELOG
=========

# v0.1.0

- Initial release of BIP39 CLI tool
- Generate mnemonics with 12, 15, 18, 21, or 24 words
- Validate BIP39 mnemonic phrases
- Convert mnemonics to seeds with optional passphrase
- Generate mnemonics from provided entropy
- Extract entropy from mnemonics
- Support for all 10 BIP39 languages
- Built on trusted rust-bitcoin/rust-bip39 library
- Shell completion generation for bash, zsh, fish, and PowerShell
- Cross-platform support (Linux, Windows, macOS, ARM64)
- Comprehensive test suite with 15+ tests
- Proper error handling with structured error types
- Security-focused design for airgapped systems