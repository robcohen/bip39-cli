use bip39::Mnemonic;
use zeroize::Zeroize;

use crate::cli::LanguageOption;
use crate::error::CliError;
use crate::security::validate_mnemonic_word_count;

pub fn handle_seed(
    mnemonic: String,
    passphrase: String,
    _secure_input: bool,
    _analyze_passphrase: bool,
    language: LanguageOption,
    quiet: bool,
    _secure_mode: bool,
) -> Result<(), CliError> {
    validate_mnemonic_word_count(&mnemonic)?;
    let mnemonic_obj = Mnemonic::parse_in_normalized(language.into(), &mnemonic)?;
    let mut seed = mnemonic_obj.to_seed(&passphrase);

    if !quiet {
        let entropy = mnemonic_obj.to_entropy();
        let word_count = mnemonic.split_whitespace().count();
        let entropy_bits = entropy.len() * 8;
        println!("Seed Generation");
        println!("════════════════");
        println!("Input words: {word_count}");
        println!("Input entropy: {entropy_bits} bits");
        println!("Output: 512 bits (64 bytes)");
        if passphrase.is_empty() {
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
