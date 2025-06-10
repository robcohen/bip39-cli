use bip39::Mnemonic;
use zeroize::Zeroize;

use crate::cli::LanguageOption;
use crate::error::CliError;
use crate::security::validate_mnemonic_word_count;

pub fn handle_seed(
    mnemonic: String,
    passphrase: String,
    secure_input: bool,
    analyze_passphrase: bool,
    language: LanguageOption,
    quiet: bool,
) -> Result<(), CliError> {
    // Handle secure input for mnemonic if requested
    let final_mnemonic = if secure_input {
        crate::security::secure_mnemonic_input("Enter mnemonic:", language.into())?
    } else {
        mnemonic
    };

    validate_mnemonic_word_count(&final_mnemonic)?;
    let mnemonic_obj = Mnemonic::parse_in_normalized(language.into(), &final_mnemonic)?;

    // Handle secure passphrase input or analysis
    let final_passphrase = if secure_input && passphrase.is_empty() {
        let mut secure_pass = crate::security::secure_input(
            "Enter passphrase for seed derivation:",
        )
        .map_err(|e| CliError::InvalidHexString {
            message: format!("Failed to read secure passphrase: {e}"),
            position: None,
            hint: "Ensure terminal supports secure input".to_string(),
        })?;

        // Always assess passphrase strength if analyzing or not quiet
        if analyze_passphrase || !quiet {
            let strength = crate::security::assess_passphrase_strength(&secure_pass);

            if !quiet {
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
    } else if analyze_passphrase && !passphrase.is_empty() {
        let strength = crate::security::assess_passphrase_strength(&passphrase);

        if !quiet {
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
            return Err(CliError::InvalidHexString {
                message: "Passphrase strength too low".to_string(),
                position: None,
                hint: "Use a longer, more complex passphrase".to_string(),
            });
        }

        passphrase
    } else {
        passphrase
    };

    let mut seed = mnemonic_obj.to_seed(&final_passphrase);

    if !quiet {
        let entropy = mnemonic_obj.to_entropy();
        let word_count = final_mnemonic.split_whitespace().count();
        let entropy_bits = entropy.len() * 8;
        println!("Seed Generation");
        println!("════════════════");
        println!("Input words: {word_count}");
        println!("Input entropy: {entropy_bits} bits");
        println!("Output: 512 bits (64 bytes)");
        if final_passphrase.is_empty() {
            println!("Passphrase: None");
        } else {
            println!("Passphrase: Used");
        }
        println!();
    }
    let encoded_seed = hex::encode(seed);
    println!("{encoded_seed}");
    seed.zeroize(); // Clear seed from memory

    Ok(())
}
