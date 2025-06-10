use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Generator, Shell};

#[derive(Parser)]
#[command(name = "bip39")]
#[command(
    about = "A CLI tool for BIP39 mnemonic operations using the trusted rust-bitcoin library"
)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Generate shell completion scripts
    #[arg(long = "generate", value_enum)]
    pub generator: Option<Shell>,

    /// Enable secure mode with enhanced security features
    #[arg(long, global = true)]
    pub secure: bool,

    /// Show security recommendations and environment check
    #[arg(long, global = true)]
    pub security_check: bool,
}

#[derive(Subcommand)]
pub enum Commands {
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

        /// Use secure input for passphrase (hidden from terminal)
        #[arg(long)]
        secure_passphrase: bool,

        /// Analyze and display entropy quality assessment
        #[arg(long)]
        analyze_entropy: bool,

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

        /// Use secure input for mnemonic (hidden from terminal)
        #[arg(long)]
        secure_input: bool,

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

        /// Use secure input for both mnemonic and passphrase
        #[arg(long)]
        secure_input: bool,

        /// Assess and display passphrase strength
        #[arg(long)]
        analyze_passphrase: bool,

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
pub enum WordCount {
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
    #[must_use]
    pub const fn to_entropy_bits(self) -> usize {
        match self {
            Self::Twelve => 128,
            Self::Fifteen => 160,
            Self::Eighteen => 192,
            Self::TwentyOne => 224,
            Self::TwentyFour => 256,
        }
    }

    #[must_use]
    pub fn to_entropy_bytes(self) -> usize {
        self.to_entropy_bits() / 8
    }

    #[must_use]
    pub const fn to_word_count(self) -> usize {
        match self {
            Self::Twelve => 12,
            Self::Fifteen => 15,
            Self::Eighteen => 18,
            Self::TwentyOne => 21,
            Self::TwentyFour => 24,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum LanguageOption {
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

impl From<LanguageOption> for bip39::Language {
    fn from(lang: LanguageOption) -> Self {
        match lang {
            LanguageOption::English => bip39::Language::English,
            LanguageOption::Japanese => bip39::Language::Japanese,
            LanguageOption::Korean => bip39::Language::Korean,
            LanguageOption::Spanish => bip39::Language::Spanish,
            LanguageOption::ChineseSimplified => bip39::Language::SimplifiedChinese,
            LanguageOption::ChineseTraditional => bip39::Language::TraditionalChinese,
            LanguageOption::French => bip39::Language::French,
            LanguageOption::Italian => bip39::Language::Italian,
            LanguageOption::Czech => bip39::Language::Czech,
            LanguageOption::Portuguese => bip39::Language::Portuguese,
        }
    }
}

pub fn print_completions<G: Generator>(gen: G, cmd: &mut clap::Command) {
    generate(gen, cmd, cmd.get_name().to_string(), &mut std::io::stdout());
}
