pub mod entropy;
pub mod generate;
pub mod seed;
pub mod validate;

use crate::cli::Commands;
use crate::error::CliError;

pub fn run_command(command: Commands) -> Result<(), CliError> {
    match command {
        Commands::Generate {
            words,
            language,
            show_entropy,
            show_seed,
            passphrase,
            secure_passphrase,
            analyze_entropy,
            quiet,
        } => generate::handle_generate(generate::GenerateOptions {
            words,
            language,
            show_entropy,
            show_seed,
            passphrase,
            secure_passphrase,
            analyze_entropy,
            quiet,
        }),

        Commands::Validate {
            mnemonic,
            language,
            secure_input,
            quiet,
        } => validate::handle_validate(mnemonic, language, secure_input, quiet),

        Commands::Seed {
            mnemonic,
            passphrase,
            secure_input,
            analyze_passphrase,
            language,
            quiet,
        } => seed::handle_seed(
            mnemonic,
            passphrase,
            secure_input,
            analyze_passphrase,
            language,
            quiet,
        ),

        Commands::FromEntropy {
            entropy,
            language,
            quiet,
        } => entropy::handle_from_entropy(entropy, language, quiet),

        Commands::Entropy {
            mnemonic,
            language,
            quiet,
        } => entropy::handle_entropy(mnemonic, language, quiet),
    }
}
