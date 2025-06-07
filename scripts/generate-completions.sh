#!/usr/bin/env bash

set -euo pipefail

# Create completions directory
mkdir -p completions

# Build the binary first
cargo build --release

# Generate shell completions
echo "Generating shell completions..."

# Bash completion
./target/release/bip39 --generate bash > completions/bip39.bash

# Zsh completion  
./target/release/bip39 --generate zsh > completions/_bip39

# Fish completion
./target/release/bip39 --generate fish > completions/bip39.fish

# PowerShell completion
./target/release/bip39 --generate powershell > completions/_bip39.ps1

echo "Shell completions generated in ./completions/"
echo "To install:"
echo "  Bash: source completions/bip39.bash or copy to /etc/bash_completion.d/"
echo "  Zsh: copy completions/_bip39 to a directory in \$fpath"
echo "  Fish: copy completions/bip39.fish to ~/.config/fish/completions/"
echo "  PowerShell: add completions/_bip39.ps1 to your profile"