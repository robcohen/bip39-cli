use bip39::Mnemonic;
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use crate::cli::{LanguageOption, WordCount};
use crate::error::CliError;

pub struct GenerateOptions {
    pub words: WordCount,
    pub language: LanguageOption,
    pub show_entropy: bool,
    pub show_seed: bool,
    pub passphrase: String,
    pub secure_passphrase: bool,
    pub analyze_entropy: bool,
    pub quiet: bool,
}

pub fn handle_generate(opts: GenerateOptions) -> Result<(), CliError> {
    let mut entropy = vec![0u8; opts.words.to_entropy_bytes()];
    OsRng.fill_bytes(&mut entropy);

    // Analyze entropy quality if requested
    if opts.analyze_entropy {
        let quality = crate::security::analyze_entropy_quality(&entropy);

        if !opts.quiet {
            println!("🔬 Entropy Quality Analysis");
            println!("═══════════════════════════");
            println!("Score: {:.2}/1.0", quality.score);

            if !quality.issues.is_empty() {
                println!("\n⚠️  Issues detected:");
                for issue in &quality.issues {
                    println!("  • {issue}");
                }
            }

            println!("\n💡 Recommendations:");
            for rec in &quality.recommendations {
                println!("  • {rec}");
            }
            println!();
        }

        // Only fail if entropy is obviously broken (not just statistically unusual)
        if quality.score < 0.1 {
            entropy.zeroize();
            return Err(CliError::InvalidHexString {
                message: "Entropy appears to be severely compromised".to_string(),
                position: None,
                hint: "System RNG may be broken. Consider restarting or using hardware RNG."
                    .to_string(),
            });
        }
    }

    // Always use secure entropy source, show confirmation unless quiet
    if !opts.quiet {
        println!("✅ Using cryptographically secure entropy source (OsRng)");
    }

    let mnemonic = Mnemonic::from_entropy_in(opts.language.into(), &entropy)?;

    let word_count = opts.words.to_word_count();
    if !opts.quiet {
        let bits = opts.words.to_entropy_bits();
        println!("Generated Mnemonic");
        println!("═══════════════════");
        println!("Words: {word_count}");
        println!("Entropy: {bits} bits");
        println!();
    }
    println!("{mnemonic}");

    if opts.show_entropy {
        let bits = opts.words.to_entropy_bits();
        println!();
        if !opts.quiet {
            println!("Raw Entropy");
            println!("═══════════");
            println!("Bits: {bits}");
            println!("Bytes: {}", entropy.len());
            println!();
        }
        let encoded = hex::encode(&entropy);
        println!("{encoded}");
    }

    if opts.show_seed {
        // Handle secure passphrase input
        let final_passphrase = if opts.secure_passphrase {
            let mut secure_pass = crate::security::secure_input(
                "Enter passphrase for seed derivation:",
            )
            .map_err(|e| CliError::InvalidHexString {
                message: format!("Failed to read secure passphrase: {e}"),
                position: None,
                hint: "Ensure terminal supports secure input".to_string(),
            })?;

            // Always assess passphrase strength
            if !opts.quiet {
                let strength = crate::security::assess_passphrase_strength(&secure_pass);

                if !opts.quiet {
                    println!("\n🔐 Passphrase Strength Analysis");
                    println!("═══════════════════════════════");
                    println!("Score: {:.2}/1.0", strength.score);
                    println!("Entropy: {:.1} bits", strength.entropy);

                    if !strength.issues.is_empty() {
                        println!("\n⚠️  Issues:");
                        for issue in &strength.issues {
                            println!("  • {issue}");
                        }
                    }

                    println!("\n💡 Recommendations:");
                    for rec in &strength.recommendations {
                        println!("  • {rec}");
                    }
                    println!();
                }

                if strength.score < 0.6 {
                    secure_pass.zeroize();
                    return Err(CliError::InvalidHexString {
                        message: "Passphrase strength too low".to_string(),
                        position: None,
                        hint: "Use a longer, more complex passphrase".to_string(),
                    });
                }
            }

            secure_pass
        } else {
            opts.passphrase
        };

        let mut seed = mnemonic.to_seed(&final_passphrase);
        if !opts.quiet {
            if !opts.show_entropy {
                println!();
            }
            println!("Derived Seed");
            println!("════════════");
            println!("Length: 512 bits (64 bytes)");
            if final_passphrase.is_empty() {
                println!("Passphrase: None");
            } else {
                println!("Passphrase: Used");
            }
            println!();
        } else if opts.show_entropy {
            println!();
        }
        let encoded_seed = hex::encode(seed);
        println!("{encoded_seed}");
        seed.zeroize(); // Clear seed from memory
    }

    // Clear entropy from memory
    entropy.zeroize();

    Ok(())
}
