pub mod cli;
pub mod commands;
pub mod error;
pub mod security;

pub use cli::Cli;
pub use error::CliError;

use clap::{CommandFactory, Parser};

pub fn run() -> Result<(), CliError> {
    let cli = Cli::parse();

    // Handle security check flag
    if cli.security_check {
        security::show_security_warnings().map_err(|e| CliError::InvalidHexString {
            message: format!("Failed to display security warnings: {e}"),
            position: None,
            hint: "Terminal may not support colored output".to_string(),
        })?;

        let air_gap_status = security::check_air_gapped_environment();
        println!("\n🔍 Air-Gap Environment Check:");
        println!("Score: {:.1}/1.0", air_gap_status.score);

        if air_gap_status.is_air_gapped {
            println!("✅ Environment appears to be air-gapped");
        } else {
            println!("⚠️  Environment may not be fully air-gapped");
            for warning in &air_gap_status.warnings {
                println!("  • {warning}");
            }
        }
        return Ok(());
    }

    if let Some(generator) = cli.generator {
        let mut cmd = Cli::command();
        cli::print_completions(generator, &mut cmd);
        return Ok(());
    }

    if let Some(command) = cli.command {
        // Show security warnings by default unless in quiet mode
        let is_quiet = match &command {
            cli::Commands::Generate { quiet, .. } => *quiet,
            cli::Commands::Validate { quiet, .. } => *quiet,
            cli::Commands::Seed { quiet, .. } => *quiet,
            cli::Commands::FromEntropy { quiet, .. } => *quiet,
            cli::Commands::Entropy { quiet, .. } => *quiet,
        };

        if !is_quiet {
            security::show_security_warnings().map_err(|e| CliError::InvalidHexString {
                message: format!("Failed to display security warnings: {e}"),
                position: None,
                hint: "Terminal may not support colored output".to_string(),
            })?;
        }

        commands::run_command(command)?;
    } else {
        return Err(CliError::NoCommandProvided);
    }

    Ok(())
}
