use std::fmt;

#[derive(Debug)]
pub enum CliError {
    InvalidEntropyLength {
        actual: usize,
        expected: Vec<usize>,
        hint: String,
    },
    InvalidHexString {
        message: String,
        position: Option<usize>,
        hint: String,
    },
    InvalidWordCount {
        actual: usize,
        expected: Vec<usize>,
        hint: String,
    },
    InvalidWord {
        word: String,
        position: usize,
        suggestions: Vec<String>,
    },
    MnemonicError(bip39::Error),
    HexDecodeError(hex::FromHexError),
    NoCommandProvided,
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEntropyLength {
                actual,
                expected,
                hint,
            } => {
                writeln!(f, "Invalid entropy length: {actual} hex characters")?;
                writeln!(f, "Expected one of: {expected:?}")?;
                write!(f, "Hint: {hint}")
            }
            Self::InvalidHexString {
                message,
                position,
                hint,
            } => {
                writeln!(f, "{message}")?;
                if let Some(pos) = position {
                    writeln!(f, "Error at position: {pos}")?;
                }
                write!(f, "Hint: {hint}")
            }
            Self::InvalidWordCount {
                actual,
                expected,
                hint,
            } => {
                writeln!(f, "Invalid mnemonic word count: {actual}")?;
                writeln!(f, "Expected one of: {expected:?}")?;
                write!(f, "Hint: {hint}")
            }
            Self::InvalidWord {
                word,
                position,
                suggestions,
            } => {
                writeln!(f, "Invalid word '{word}' at position {position}")?;
                if !suggestions.is_empty() {
                    writeln!(f, "Did you mean one of: {suggestions:?}")?;
                }
                write!(
                    f,
                    "Hint: Check spelling and ensure the word is from the BIP39 word list"
                )
            }
            Self::MnemonicError(e) => write!(f, "BIP39 error: {e}"),
            Self::HexDecodeError(e) => {
                writeln!(f, "Hex decode error: {e}")?;
                write!(
                    f,
                    "Hint: Ensure the string contains only valid hex characters (0-9, a-f, A-F)"
                )
            }
            Self::NoCommandProvided => {
                write!(f, "No command provided. Use --help for usage information.")
            }
        }
    }
}

impl std::error::Error for CliError {}

impl From<bip39::Error> for CliError {
    fn from(error: bip39::Error) -> Self {
        Self::MnemonicError(error)
    }
}

impl From<hex::FromHexError> for CliError {
    fn from(error: hex::FromHexError) -> Self {
        Self::HexDecodeError(error)
    }
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        Self::InvalidHexString {
            message: format!("IO error: {error}"),
            position: None,
            hint: "Check terminal permissions and capabilities".to_string(),
        }
    }
}
