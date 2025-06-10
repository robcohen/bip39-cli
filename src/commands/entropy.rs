use bip39::Mnemonic;
use zeroize::Zeroize;

use crate::cli::LanguageOption;
use crate::error::CliError;
use crate::security::{validate_entropy_hex, validate_mnemonic_word_count};

pub fn handle_from_entropy(
    entropy: String,
    language: LanguageOption,
    quiet: bool,
) -> Result<(), CliError> {
    validate_entropy_hex(&entropy)?;
    let mut entropy_bytes = hex::decode(&entropy)?;
    let mnemonic = Mnemonic::from_entropy_in(language.into(), &entropy_bytes)?;

    let word_count = match entropy_bytes.len() {
        16 => 12,
        20 => 15,
        24 => 18,
        28 => 21,
        32 => 24,
        _ => {
            return Err(CliError::InvalidEntropyLength {
                actual: entropy_bytes.len() * 2, // Convert bytes to hex chars for consistency
                expected: vec![32, 40, 48, 56, 64],
                hint: "Check the entropy length and ensure it matches a valid word count"
                    .to_string(),
            });
        }
    };
    if !quiet {
        let bits = entropy_bytes.len() * 8;
        println!("Mnemonic from Entropy");
        println!("══════════════════════");
        println!("Input entropy: {bits} bits ({} bytes)", entropy_bytes.len());
        println!("Output words: {word_count}");
        println!("Language: {language:?}");
        println!();
    }
    println!("{mnemonic}");
    entropy_bytes.zeroize(); // Clear entropy from memory

    Ok(())
}

pub fn handle_entropy(
    mnemonic: String,
    language: LanguageOption,
    quiet: bool,
) -> Result<(), CliError> {
    validate_mnemonic_word_count(&mnemonic)?;
    let mnemonic_obj = Mnemonic::parse_in_normalized(language.into(), &mnemonic)?;
    let entropy = mnemonic_obj.to_entropy();

    let bits = entropy.len() * 8;
    if !quiet {
        let word_count = mnemonic.split_whitespace().count();
        println!("Entropy Extraction");
        println!("═══════════════════");
        println!("Input words: {word_count}");
        println!("Output entropy: {bits} bits ({} bytes)", entropy.len());
        println!("Language: {language:?}");
        println!();
    }
    let encoded_entropy = hex::encode(entropy);
    println!("{encoded_entropy}");

    Ok(())
}
