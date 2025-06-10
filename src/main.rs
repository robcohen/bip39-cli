use bip39::{Language, Mnemonic};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Generator, Shell};
use rand::{rngs::OsRng, RngCore};
use std::fmt;

#[derive(Parser)]
#[command(name = "bip39")]
#[command(
    about = "A CLI tool for BIP39 mnemonic operations using the trusted rust-bitcoin library"
)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Generate shell completion scripts
    #[arg(long = "generate", value_enum)]
    generator: Option<Shell>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new mnemonic phrase
    Generate {
        /// Number of words in the mnemonic (12, 15, 18, 21, or 24)
        #[arg(short, long)]
        words: WordCount,

        /// Language for the mnemonic
        #[arg(short, long, default_value = "english")]
        language: LanguageOption,

        /// Show entropy used to generate the mnemonic
        #[arg(long)]
        show_entropy: bool,

        /// Show seed derived from the mnemonic
        #[arg(long)]
        show_seed: bool,

        /// Passphrase for seed derivation (only used with --show-seed)
        #[arg(long, default_value = "")]
        passphrase: String,

        /// Output only raw data without headers (useful for piping)
        #[arg(short, long)]
        quiet: bool,
    },

    /// Validate a mnemonic phrase
    Validate {
        /// The mnemonic phrase to validate (space-separated words)
        mnemonic: String,

        /// Language of the mnemonic
        #[arg(short, long, default_value = "english")]
        language: LanguageOption,

        /// Output only raw data without headers (useful for piping)
        #[arg(short, long)]
        quiet: bool,
    },

    /// Convert mnemonic to seed
    Seed {
        /// The mnemonic phrase (space-separated words)
        mnemonic: String,

        /// Passphrase for seed derivation
        #[arg(short, long, default_value = "")]
        passphrase: String,

        /// Language of the mnemonic
        #[arg(short, long, default_value = "english")]
        language: LanguageOption,

        /// Output only raw data without headers (useful for piping)
        #[arg(short, long)]
        quiet: bool,
    },

    /// Generate mnemonic from provided entropy
    FromEntropy {
        /// Entropy as hex string (32, 40, 48, 56, or 64 hex chars for 12, 15, 18, 21, or 24 words)
        entropy: String,

        /// Language for the mnemonic
        #[arg(short, long, default_value = "english")]
        language: LanguageOption,

        /// Output only raw data without headers (useful for piping)
        #[arg(short, long)]
        quiet: bool,
    },

    /// Get entropy from a mnemonic
    Entropy {
        /// The mnemonic phrase (space-separated words)
        mnemonic: String,

        /// Language of the mnemonic
        #[arg(short, long, default_value = "english")]
        language: LanguageOption,

        /// Output only raw data without headers (useful for piping)
        #[arg(short, long)]
        quiet: bool,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum WordCount {
    #[value(name = "12")]
    Twelve,
    #[value(name = "15")]
    Fifteen,
    #[value(name = "18")]
    Eighteen,
    #[value(name = "21")]
    TwentyOne,
    #[value(name = "24")]
    TwentyFour,
}

impl WordCount {
    fn to_entropy_bits(self) -> usize {
        match self {
            WordCount::Twelve => 128,
            WordCount::Fifteen => 160,
            WordCount::Eighteen => 192,
            WordCount::TwentyOne => 224,
            WordCount::TwentyFour => 256,
        }
    }

    fn to_entropy_bytes(self) -> usize {
        self.to_entropy_bits() / 8
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum LanguageOption {
    English,
    Japanese,
    Korean,
    Spanish,
    ChineseSimplified,
    ChineseTraditional,
    French,
    Italian,
    Czech,
    Portuguese,
}

impl From<LanguageOption> for Language {
    fn from(lang: LanguageOption) -> Self {
        match lang {
            LanguageOption::English => Language::English,
            LanguageOption::Japanese => Language::Japanese,
            LanguageOption::Korean => Language::Korean,
            LanguageOption::Spanish => Language::Spanish,
            LanguageOption::ChineseSimplified => Language::SimplifiedChinese,
            LanguageOption::ChineseTraditional => Language::TraditionalChinese,
            LanguageOption::French => Language::French,
            LanguageOption::Italian => Language::Italian,
            LanguageOption::Czech => Language::Czech,
            LanguageOption::Portuguese => Language::Portuguese,
        }
    }
}

fn print_completions<G: Generator>(gen: G, cmd: &mut clap::Command) {
    generate(gen, cmd, cmd.get_name().to_string(), &mut std::io::stdout());
}

fn main() {
    let cli = Cli::parse();

    if let Some(generator) = cli.generator {
        let mut cmd = Cli::command();
        print_completions(generator, &mut cmd);
        return;
    }

    if let Some(command) = cli.command {
        if let Err(e) = run_command(command) {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    } else {
        eprintln!("Error: No command provided. Use --help for usage information.");
        std::process::exit(1);
    }
}

#[derive(Debug)]
enum CliError {
    InvalidEntropyLength { actual: usize, expected: Vec<usize> },
    InvalidHexString(String),
    InvalidWordCount { actual: usize, expected: Vec<usize> },
    MnemonicError(bip39::Error),
    HexDecodeError(hex::FromHexError),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::InvalidEntropyLength { actual, expected } => {
                write!(
                    f,
                    "Invalid entropy length: {actual} hex chars. Expected one of: {expected:?}"
                )
            }
            CliError::InvalidHexString(msg) => write!(f, "{msg}"),
            CliError::InvalidWordCount { actual, expected } => {
                write!(
                    f,
                    "Invalid mnemonic word count: {actual}. Expected one of: {expected:?}"
                )
            }
            CliError::MnemonicError(e) => write!(f, "BIP39 error: {e}"),
            CliError::HexDecodeError(e) => write!(f, "Hex decode error: {e}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<bip39::Error> for CliError {
    fn from(error: bip39::Error) -> Self {
        CliError::MnemonicError(error)
    }
}

impl From<hex::FromHexError> for CliError {
    fn from(error: hex::FromHexError) -> Self {
        CliError::HexDecodeError(error)
    }
}

fn validate_entropy_hex(hex_str: &str) -> Result<(), CliError> {
    let expected_lengths = vec![32, 40, 48, 56, 64]; // 16, 20, 24, 28, 32 bytes
    if !expected_lengths.contains(&hex_str.len()) {
        return Err(CliError::InvalidEntropyLength {
            actual: hex_str.len(),
            expected: expected_lengths,
        });
    }

    if !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CliError::InvalidHexString(
            "Entropy must be a valid hex string".to_string(),
        ));
    }

    Ok(())
}

fn validate_mnemonic_word_count(mnemonic: &str) -> Result<(), CliError> {
    let word_count = mnemonic.split_whitespace().count();
    let valid_counts = vec![12, 15, 18, 21, 24];

    if !valid_counts.contains(&word_count) {
        return Err(CliError::InvalidWordCount {
            actual: word_count,
            expected: valid_counts,
        });
    }

    Ok(())
}

fn run_command(command: Commands) -> Result<(), CliError> {
    match command {
        Commands::Generate {
            words,
            language,
            show_entropy,
            show_seed,
            passphrase,
            quiet,
        } => {
            let mut entropy = vec![0u8; words.to_entropy_bytes()];
            OsRng.fill_bytes(&mut entropy);

            let mnemonic = Mnemonic::from_entropy_in(language.into(), &entropy)?;

            let word_count = match words {
                WordCount::Twelve => 12,
                WordCount::Fifteen => 15,
                WordCount::Eighteen => 18,
                WordCount::TwentyOne => 21,
                WordCount::TwentyFour => 24,
            };
            if !quiet {
                let bits = words.to_entropy_bits();
                println!("Generated Mnemonic");
                println!("═══════════════════");
                println!("Words: {word_count}");
                println!("Entropy: {bits} bits");
                println!();
            }
            println!("{mnemonic}");

            if show_entropy {
                let bits = words.to_entropy_bits();
                if !quiet {
                    println!();
                    println!("Raw Entropy");
                    println!("═══════════");
                    println!("Bits: {bits}");
                    println!("Bytes: {}", entropy.len());
                    println!();
                } else {
                    println!();
                }
                let encoded = hex::encode(&entropy);
                println!("{encoded}");
            }

            if show_seed {
                let seed = mnemonic.to_seed(&passphrase);
                if !quiet {
                    if !show_entropy {
                        println!();
                    }
                    println!("Derived Seed");
                    println!("════════════");
                    println!("Length: 512 bits (64 bytes)");
                    if !passphrase.is_empty() {
                        println!("Passphrase: Used");
                    } else {
                        println!("Passphrase: None");
                    }
                    println!();
                } else if show_entropy {
                    println!();
                }
                let encoded_seed = hex::encode(seed);
                println!("{encoded_seed}");
            }
        }

        Commands::Validate { mnemonic, language, quiet } => {
            validate_mnemonic_word_count(&mnemonic)?;
            match Mnemonic::parse_in_normalized(language.into(), &mnemonic) {
                Ok(parsed_mnemonic) => {
                    if quiet {
                        println!("valid");
                    } else {
                        let entropy = parsed_mnemonic.to_entropy();
                        let word_count = mnemonic.split_whitespace().count();
                        let bits = entropy.len() * 8;
                        println!("Mnemonic Validation");
                        println!("═══════════════════");
                        println!("✓ Status: Valid BIP39 mnemonic");
                        println!("Words: {word_count}");
                        println!("Entropy: {bits} bits");
                        println!("Language: {:?}", language);
                    }
                }
                Err(e) => {
                    if quiet {
                        println!("invalid");
                    } else {
                        let word_count = mnemonic.split_whitespace().count();
                        println!("Mnemonic Validation");
                        println!("═══════════════════");
                        println!("✗ Status: Invalid BIP39 mnemonic");
                        println!("Words: {word_count}");
                        println!("Error: {e}");
                        println!("Language: {:?}", language);
                    }
                    std::process::exit(1);
                }
            }
        }

        Commands::Seed {
            mnemonic,
            passphrase,
            language,
            quiet,
        } => {
            validate_mnemonic_word_count(&mnemonic)?;
            let mnemonic_obj = Mnemonic::parse_in_normalized(language.into(), &mnemonic)?;
            let seed = mnemonic_obj.to_seed(&passphrase);

            if !quiet {
                let entropy = mnemonic_obj.to_entropy();
                let word_count = mnemonic.split_whitespace().count();
                let entropy_bits = entropy.len() * 8;
                println!("Seed Generation");
                println!("════════════════");
                println!("Input words: {word_count}");
                println!("Input entropy: {entropy_bits} bits");
                println!("Output: 512 bits (64 bytes)");
                if !passphrase.is_empty() {
                    println!("Passphrase: Used");
                } else {
                    println!("Passphrase: None");
                }
                println!();
            }
            let encoded_seed = hex::encode(seed);
            println!("{encoded_seed}");
        }

        Commands::FromEntropy { entropy, language, quiet } => {
            validate_entropy_hex(&entropy)?;
            let entropy_bytes = hex::decode(&entropy)?;
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
                    });
                }
            };
            if !quiet {
                let bits = entropy_bytes.len() * 8;
                println!("Mnemonic from Entropy");
                println!("══════════════════════");
                println!("Input entropy: {bits} bits ({} bytes)", entropy_bytes.len());
                println!("Output words: {word_count}");
                println!("Language: {:?}", language);
                println!();
            }
            println!("{mnemonic}");
        }

        Commands::Entropy { mnemonic, language, quiet } => {
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
                println!("Language: {:?}", language);
                println!();
            }
            let encoded_entropy = hex::encode(&entropy);
            println!("{encoded_entropy}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;

    #[test]
    fn test_word_count_entropy_conversion() {
        assert_eq!(WordCount::Twelve.to_entropy_bits(), 128);
        assert_eq!(WordCount::Twelve.to_entropy_bytes(), 16);
        assert_eq!(WordCount::Fifteen.to_entropy_bits(), 160);
        assert_eq!(WordCount::Fifteen.to_entropy_bytes(), 20);
        assert_eq!(WordCount::Eighteen.to_entropy_bits(), 192);
        assert_eq!(WordCount::Eighteen.to_entropy_bytes(), 24);
        assert_eq!(WordCount::TwentyOne.to_entropy_bits(), 224);
        assert_eq!(WordCount::TwentyOne.to_entropy_bytes(), 28);
        assert_eq!(WordCount::TwentyFour.to_entropy_bits(), 256);
        assert_eq!(WordCount::TwentyFour.to_entropy_bytes(), 32);
    }

    #[test]
    fn test_language_conversion() {
        assert_eq!(Language::from(LanguageOption::English), Language::English);
        assert_eq!(Language::from(LanguageOption::Japanese), Language::Japanese);
        assert_eq!(Language::from(LanguageOption::Korean), Language::Korean);
        assert_eq!(Language::from(LanguageOption::Spanish), Language::Spanish);
        assert_eq!(
            Language::from(LanguageOption::ChineseSimplified),
            Language::SimplifiedChinese
        );
        assert_eq!(
            Language::from(LanguageOption::ChineseTraditional),
            Language::TraditionalChinese
        );
        assert_eq!(Language::from(LanguageOption::French), Language::French);
        assert_eq!(Language::from(LanguageOption::Italian), Language::Italian);
        assert_eq!(Language::from(LanguageOption::Czech), Language::Czech);
        assert_eq!(
            Language::from(LanguageOption::Portuguese),
            Language::Portuguese
        );
    }

    #[test]
    fn test_validate_entropy_hex() {
        // Valid entropy lengths
        assert!(validate_entropy_hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf").is_ok()); // 32 chars = 16 bytes
        assert!(validate_entropy_hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3").is_ok()); // 40 chars = 20 bytes
        assert!(validate_entropy_hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7").is_ok()); // 48 chars = 24 bytes
        assert!(
            validate_entropy_hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babb")
                .is_ok()
        ); // 56 chars = 28 bytes
        assert!(validate_entropy_hex(
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        )
        .is_ok()); // 64 chars = 32 bytes

        // Invalid entropy lengths
        assert!(validate_entropy_hex("a0a1a2a3").is_err()); // 8 chars
        assert!(validate_entropy_hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0").is_err()); // 34 chars

        // Invalid hex characters
        assert!(validate_entropy_hex("g0a1a2a3a4a5a6a7a8a9aaabacadaeaf").is_err());
        assert!(validate_entropy_hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaZ").is_err());
    }

    #[test]
    fn test_validate_mnemonic_word_count() {
        // Valid word counts
        assert!(validate_mnemonic_word_count("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").is_ok()); // 12 words
        assert!(validate_mnemonic_word_count("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").is_ok()); // 15 words

        // Invalid word counts
        assert!(validate_mnemonic_word_count("abandon abandon abandon").is_err()); // 3 words
        assert!(validate_mnemonic_word_count("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon").is_err()); // 11 words
        assert!(validate_mnemonic_word_count("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon").is_err());
        // 13 words
    }

    #[test]
    fn test_generate_command_logic() {
        // Test the logic without actually running the command that prints to stdout
        for words in [
            WordCount::Twelve,
            WordCount::Fifteen,
            WordCount::Eighteen,
            WordCount::TwentyOne,
            WordCount::TwentyFour,
        ] {
            let mut entropy = vec![0u8; words.to_entropy_bytes()];
            rand::rngs::OsRng.fill_bytes(&mut entropy);
            let result = Mnemonic::from_entropy_in(LanguageOption::English.into(), &entropy);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_validate_command_logic() {
        let valid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result = Mnemonic::parse_in_normalized(LanguageOption::English.into(), valid_mnemonic);
        assert!(result.is_ok());
    }

    #[test]
    fn test_seed_command_logic() {
        let valid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic =
            Mnemonic::parse_in_normalized(LanguageOption::English.into(), valid_mnemonic).unwrap();
        let seed = mnemonic.to_seed("");
        assert_eq!(seed.len(), 64); // BIP39 seeds are always 64 bytes
    }

    #[test]
    fn test_from_entropy_command_logic() {
        let valid_entropy = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"; // 128 bits for 12 words
        let entropy_bytes = hex::decode(valid_entropy).unwrap();
        let result = Mnemonic::from_entropy_in(LanguageOption::English.into(), &entropy_bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_entropy_command_logic() {
        let valid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic =
            Mnemonic::parse_in_normalized(LanguageOption::English.into(), valid_mnemonic).unwrap();
        let entropy = mnemonic.to_entropy();
        assert_eq!(entropy.len(), 16); // 12 words = 128 bits = 16 bytes
    }

    #[test]
    fn test_all_languages() {
        // Test that language conversion works properly
        for language in [
            LanguageOption::English,
            LanguageOption::Japanese,
            LanguageOption::Korean,
        ] {
            let bip39_lang: Language = language.into();
            // Just verify the conversion works - we can't test non-English mnemonics
            // without actual valid mnemonics in those languages
            assert!(matches!(
                bip39_lang,
                Language::English | Language::Japanese | Language::Korean
            ));
        }
    }

    #[test]
    fn test_deterministic_from_entropy() {
        let entropy = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";

        // Generate mnemonic from same entropy twice
        let mnemonic1 =
            Mnemonic::from_entropy_in(Language::English, &hex::decode(entropy).unwrap()).unwrap();
        let mnemonic2 =
            Mnemonic::from_entropy_in(Language::English, &hex::decode(entropy).unwrap()).unwrap();

        assert_eq!(mnemonic1.to_string(), mnemonic2.to_string());
    }

    #[test]
    fn test_seed_with_passphrase() {
        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_str).unwrap();

        let seed_no_passphrase = mnemonic.to_seed("");
        let seed_with_passphrase = mnemonic.to_seed("test_passphrase");

        // Seeds should be different with different passphrases
        assert_ne!(seed_no_passphrase, seed_with_passphrase);
    }

    #[test]
    fn test_cli_error_display() {
        let error = CliError::InvalidEntropyLength {
            actual: 8,
            expected: vec![32, 40, 48, 56, 64],
        };
        assert!(error
            .to_string()
            .contains("Invalid entropy length: 8 hex chars"));

        let error = CliError::InvalidWordCount {
            actual: 11,
            expected: vec![12, 15, 18, 21, 24],
        };
        assert!(error
            .to_string()
            .contains("Invalid mnemonic word count: 11"));

        let error = CliError::InvalidHexString("Test error".to_string());
        assert_eq!(error.to_string(), "Test error");
    }

    #[test]
    fn test_error_conversion() {
        // Test that bip39::Error converts to CliError
        let hex_error = hex::FromHexError::InvalidStringLength;
        let cli_error = CliError::from(hex_error);
        assert!(matches!(cli_error, CliError::HexDecodeError(_)));
    }

    #[test]
    fn test_edge_cases() {
        // Test empty string validation
        assert!(validate_mnemonic_word_count("").is_err());
        assert!(validate_entropy_hex("").is_err());

        // Test whitespace handling
        assert!(validate_mnemonic_word_count("   ").is_err());
        assert!(validate_mnemonic_word_count("word1  word2   word3").is_err()); // 3 words

        // Test case sensitivity in hex
        assert!(validate_entropy_hex("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF").is_ok());
        assert!(validate_entropy_hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf").is_ok());
    }
}
