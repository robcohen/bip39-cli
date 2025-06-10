use bip39::Mnemonic;

use crate::cli::LanguageOption;
use crate::error::CliError;
use crate::security::{find_invalid_words, validate_mnemonic_word_count};

pub fn handle_validate(
    mnemonic: String,
    language: LanguageOption,
    secure_input: bool,
    quiet: bool,
) -> Result<(), CliError> {
    let final_mnemonic = if secure_input {
        crate::security::secure_mnemonic_input("Enter mnemonic to validate:", language.into())?
    } else {
        mnemonic
    };
    validate_mnemonic_word_count(&final_mnemonic)?;

    let bip39_language = language.into();

    match Mnemonic::parse_in_normalized(bip39_language, &final_mnemonic) {
        Ok(parsed_mnemonic) => {
            if quiet {
                println!("valid");
            } else {
                let entropy = parsed_mnemonic.to_entropy();
                let word_count = final_mnemonic.split_whitespace().count();
                let bits = entropy.len() * 8;
                println!("Mnemonic Validation");
                println!("═══════════════════");
                println!("✓ Status: Valid BIP39 mnemonic");
                println!("Words: {word_count}");
                println!("Entropy: {bits} bits");
                println!("Language: {language:?}");
            }
            Ok(())
        }
        Err(e) => {
            // Check for invalid words first and provide helpful feedback
            let invalid_words = find_invalid_words(&final_mnemonic, bip39_language);
            if !invalid_words.is_empty() {
                let (position, word, suggestions) = &invalid_words[0];
                return Err(CliError::InvalidWord {
                    word: word.clone(),
                    position: *position,
                    suggestions: suggestions.clone(),
                });
            }

            if quiet {
                println!("invalid");
            } else {
                let word_count = final_mnemonic.split_whitespace().count();
                println!("Mnemonic Validation");
                println!("═══════════════════");
                println!("✗ Status: Invalid BIP39 mnemonic");
                println!("Words: {word_count}");
                println!("Error: {e}");
                println!("Language: {language:?}");
            }
            std::process::exit(1);
        }
    }
}
