use console::{Style, Term};
use zeroize::Zeroize;

/// Securely clear sensitive data from memory
pub fn clear_sensitive_data<T: Zeroize>(mut data: T) -> T {
    data.zeroize();
    data
}

/// Validate entropy hex string with detailed error reporting
pub fn validate_entropy_hex(hex_str: &str) -> Result<(), crate::error::CliError> {
    let expected_lengths = vec![32, 40, 48, 56, 64]; // 16, 20, 24, 28, 32 bytes

    if !expected_lengths.contains(&hex_str.len()) {
        return Err(crate::error::CliError::InvalidEntropyLength {
            actual: hex_str.len(),
            expected: expected_lengths,
            hint: format!(
                "For {} words, use {} hex characters",
                match hex_str.len() {
                    l if l < 32 => "12",
                    l if l < 40 => "15",
                    l if l < 48 => "18",
                    l if l < 56 => "21",
                    _ => "24",
                },
                if hex_str.len() < 32 {
                    32
                } else if hex_str.len() < 40 {
                    40
                } else if hex_str.len() < 48 {
                    48
                } else if hex_str.len() < 56 {
                    56
                } else {
                    64
                }
            ),
        });
    }

    // Find first invalid character position
    for (i, c) in hex_str.chars().enumerate() {
        if !c.is_ascii_hexdigit() {
            return Err(crate::error::CliError::InvalidHexString {
                message: "Entropy must be a valid hex string".to_string(),
                position: Some(i),
                hint: "Use only characters 0-9, a-f, A-F".to_string(),
            });
        }
    }

    Ok(())
}

/// Validate mnemonic word count with helpful suggestions
pub fn validate_mnemonic_word_count(mnemonic: &str) -> Result<(), crate::error::CliError> {
    let word_count = mnemonic.split_whitespace().count();
    let valid_counts = vec![12, 15, 18, 21, 24];

    if !valid_counts.contains(&word_count) {
        let closest_count = valid_counts
            .iter()
            .min_by_key(|&&count| (count as i32 - word_count as i32).abs())
            .unwrap();

        return Err(crate::error::CliError::InvalidWordCount {
            actual: word_count,
            expected: valid_counts.clone(),
            hint: format!(
                "Closest valid count is {closest_count} words. Use 'bip39 generate --words {closest_count}' to generate a valid mnemonic"
            ),
        });
    }

    Ok(())
}

/// Find invalid words in a mnemonic with suggestions
#[must_use]
pub fn find_invalid_words(
    mnemonic: &str,
    language: bip39::Language,
) -> Vec<(usize, String, Vec<String>)> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    let word_list = language.word_list();
    let mut invalid_words = Vec::new();

    for (index, word) in words.iter().enumerate() {
        let word_lower = word.to_lowercase();
        if !word_list.contains(&word_lower.as_str()) {
            // Find similar words using simple edit distance
            let suggestions: Vec<String> = word_list
                .iter()
                .filter(|&w| edit_distance(&word_lower, w) <= 2)
                .take(3)
                .map(std::string::ToString::to_string)
                .collect();

            invalid_words.push((index + 1, (*word).to_string(), suggestions));
        }
    }

    invalid_words
}

/// Simple edit distance calculation for word suggestions
#[must_use]
pub fn edit_distance(s1: &str, s2: &str) -> usize {
    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();
    let m = s1_chars.len();
    let n = s2_chars.len();

    let mut dp = vec![vec![0; n + 1]; m + 1];

    for (i, row) in dp.iter_mut().enumerate().take(m + 1) {
        row[0] = i;
    }
    for j in 0..=n {
        dp[0][j] = j;
    }

    for i in 1..=m {
        for j in 1..=n {
            if s1_chars[i - 1] == s2_chars[j - 1] {
                dp[i][j] = dp[i - 1][j - 1];
            } else {
                dp[i][j] = 1 + dp[i - 1][j].min(dp[i][j - 1]).min(dp[i - 1][j - 1]);
            }
        }
    }

    dp[m][n]
}

/// Secure input for sensitive data (hidden from terminal history)
pub fn secure_input(prompt: &str) -> Result<String, std::io::Error> {
    let term = Term::stderr();
    let prompt_style = Style::new().bold().cyan();

    term.write_line(&format!("{}", prompt_style.apply_to(prompt)))?;
    term.write_str("🔒 ")?;

    match rpassword::read_password() {
        Ok(mut input) => {
            let result = input.clone();
            input.zeroize(); // Clear the input from memory
            Ok(result)
        }
        Err(e) => Err(e),
    }
}

/// Secure input for mnemonics with validation
pub fn secure_mnemonic_input(
    prompt: &str,
    language: bip39::Language,
) -> Result<String, crate::error::CliError> {
    let warning_style = Style::new().bold().yellow();
    let term = Term::stderr();

    term.write_line(&format!(
        "{}",
        warning_style.apply_to("⚠️  SECURITY WARNING")
    ))?;
    term.write_line("• Never share your mnemonic phrase")?;
    term.write_line("• Ensure you're on a secure, private computer")?;
    term.write_line("• Consider using an air-gapped system for maximum security")?;
    term.write_line("")?;

    let mut mnemonic =
        secure_input(prompt).map_err(|e| crate::error::CliError::InvalidHexString {
            message: format!("Failed to read secure input: {e}"),
            position: None,
            hint: "Ensure terminal supports secure input".to_string(),
        })?;

    // Validate the mnemonic
    validate_mnemonic_word_count(&mnemonic)?;

    // Check for invalid words
    let invalid_words = find_invalid_words(&mnemonic, language);
    if !invalid_words.is_empty() {
        mnemonic.zeroize();
        let (position, word, suggestions) = &invalid_words[0];
        return Err(crate::error::CliError::InvalidWord {
            word: word.clone(),
            position: *position,
            suggestions: suggestions.clone(),
        });
    }

    Ok(mnemonic)
}

/// Entropy quality assessment
#[derive(Debug, Clone)]
pub struct EntropyQuality {
    pub score: f64, // 0.0 to 1.0
    pub issues: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Analyze entropy quality using various statistical tests
#[must_use]
pub fn analyze_entropy_quality(entropy: &[u8]) -> EntropyQuality {
    let mut issues = Vec::new();
    let mut recommendations = Vec::new();
    let mut score = 1.0;

    // 1. Check for all zeros or all ones
    if entropy.iter().all(|&b| b == 0) {
        issues.push("Entropy is all zeros - this is extremely insecure".to_string());
        score = 0.0;
    } else if entropy.iter().all(|&b| b == 0xFF) {
        issues.push("Entropy is all ones - this is extremely insecure".to_string());
        score = 0.0;
    }

    // 2. Check for repeating patterns
    if has_repeating_pattern(entropy) {
        issues.push("Detected repeating patterns in entropy".to_string());
        score *= 0.3;
    }

    // 3. Byte frequency analysis
    let freq_score = byte_frequency_test(entropy);
    if freq_score < 0.7 {
        issues.push("Poor byte distribution detected".to_string());
        score *= freq_score;
    }

    // 4. Sequential pattern detection
    if has_sequential_pattern(entropy) {
        issues.push("Sequential patterns detected (e.g., counting sequences)".to_string());
        score *= 0.5;
    }

    // 5. Entropy estimation using Shannon entropy
    let shannon_entropy = calculate_shannon_entropy(entropy);
    let max_entropy = 8.0; // Maximum entropy for bytes
    let entropy_ratio = shannon_entropy / max_entropy;

    if entropy_ratio < 0.8 {
        issues.push(format!(
            "Low Shannon entropy: {shannon_entropy:.2} bits per byte"
        ));
        score *= entropy_ratio;
    }

    // Generate recommendations
    if score < 0.5 {
        recommendations.push(
            "🚨 CRITICAL: Generate new entropy using a cryptographically secure source".to_string(),
        );
        recommendations
            .push("Consider using: /dev/urandom, hardware RNG, or dice-based methods".to_string());
    } else if score < 0.8 {
        recommendations.push("⚠️  Consider regenerating entropy for maximum security".to_string());
        recommendations.push("Verify your entropy source is cryptographically secure".to_string());
    } else {
        recommendations.push("✅ Entropy quality appears good".to_string());
    }

    EntropyQuality {
        score,
        issues,
        recommendations,
    }
}

/// Check for simple repeating patterns
fn has_repeating_pattern(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    // Check for 2-byte patterns
    for i in 0..data.len() - 3 {
        if data[i] == data[i + 2] && data[i + 1] == data[i + 3] {
            return true;
        }
    }

    // Check for 4-byte patterns
    for i in 0..data.len() - 7 {
        if data[i..i + 4] == data[i + 4..i + 8] {
            return true;
        }
    }

    false
}

/// Byte frequency test - checks if bytes are roughly uniformly distributed
fn byte_frequency_test(data: &[u8]) -> f64 {
    let mut counts = [0u32; 256];

    for &byte in data {
        counts[byte as usize] += 1;
    }

    let expected = data.len() as f64 / 256.0;
    let mut chi_squared = 0.0;

    for count in &counts {
        let diff = f64::from(*count) - expected;
        chi_squared += (diff * diff) / expected;
    }

    // Normalize chi-squared to a 0-1 score
    // This is a simplified heuristic
    let max_chi_squared = data.len() as f64 * 4.0;
    1.0 - (chi_squared / max_chi_squared).min(1.0)
}

/// Check for sequential patterns like 01234567 or FEDCBA98
fn has_sequential_pattern(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    let mut ascending = 0;
    let mut descending = 0;

    for i in 1..data.len() {
        if data[i] == data[i - 1].wrapping_add(1) {
            ascending += 1;
        } else {
            ascending = 0;
        }

        if data[i] == data[i - 1].wrapping_sub(1) {
            descending += 1;
        } else {
            descending = 0;
        }

        if ascending >= 3 || descending >= 3 {
            return true;
        }
    }

    false
}

/// Calculate Shannon entropy
fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    let mut counts = [0u32; 256];

    for &byte in data {
        counts[byte as usize] += 1;
    }

    let total = data.len() as f64;
    let mut entropy = 0.0;

    for count in &counts {
        if *count > 0 {
            let p = f64::from(*count) / total;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Security warnings and recommendations
pub fn show_security_warnings() -> Result<(), std::io::Error> {
    let term = Term::stderr();
    let warning_style = Style::new().bold().yellow();
    let critical_style = Style::new().bold().red();
    let info_style = Style::new().bold().blue();

    term.write_line(&format!(
        "{}",
        critical_style.apply_to("🔐 SECURITY RECOMMENDATIONS")
    ))?;
    term.write_line("")?;

    term.write_line(&format!(
        "{}",
        warning_style.apply_to("ENVIRONMENT SECURITY:")
    ))?;
    term.write_line("• Use an air-gapped computer for maximum security")?;
    term.write_line("• Ensure no network connections during operation")?;
    term.write_line("• Disable swap/hibernation to prevent disk writes")?;
    term.write_line("• Use a live USB/CD Linux distribution")?;
    term.write_line("")?;

    term.write_line(&format!("{}", warning_style.apply_to("MNEMONIC SECURITY:")))?;
    term.write_line("• Never share your mnemonic phrase with anyone")?;
    term.write_line("• Store physical backups in secure locations")?;
    term.write_line("• Consider using steel/metal backup plates")?;
    term.write_line("• Test recovery before funding wallets")?;
    term.write_line("")?;

    term.write_line(&format!(
        "{}",
        warning_style.apply_to("OPERATIONAL SECURITY:")
    ))?;
    term.write_line("• Clear terminal history after use")?;
    term.write_line("• Reboot system to clear memory")?;
    term.write_line("• Use secure input modes when available")?;
    term.write_line("• Verify software integrity before use")?;
    term.write_line("")?;

    term.write_line(&format!(
        "{}",
        info_style.apply_to("⚡ Use --secure flag for enhanced security mode")
    ))?;
    term.write_line("")?;

    Ok(())
}

/// Check if we're likely running in an air-gapped environment
#[must_use]
pub fn check_air_gapped_environment() -> AirGapStatus {
    let mut warnings = Vec::new();
    let mut score = 1.0;

    // Check network interfaces (simplified check)
    if std::path::Path::new("/sys/class/net").exists() {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            let mut active_interfaces = 0;
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str != "lo" {
                    // Skip loopback
                    active_interfaces += 1;
                }
            }

            if active_interfaces > 0 {
                warnings.push(
                    "Network interfaces detected - consider disconnecting for air-gapped operation"
                        .to_string(),
                );
                score *= 0.7;
            }
        }
    }

    // Check for common signs of network activity
    if std::path::Path::new("/tmp/.X11-unix").exists() {
        warnings.push("X11 server detected - be cautious of screen capture malware".to_string());
        score *= 0.9;
    }

    // Check if we're running in a VM (basic check)
    if std::path::Path::new("/sys/class/dmi/id/product_name").exists() {
        if let Ok(product) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
            if product.to_lowercase().contains("virtual")
                || product.to_lowercase().contains("vmware")
            {
                warnings
                    .push("Virtual machine detected - ensure it's properly isolated".to_string());
                score *= 0.8;
            }
        }
    }

    AirGapStatus {
        score,
        is_air_gapped: score > 0.8 && warnings.is_empty(),
        warnings,
    }
}

#[derive(Debug, Clone)]
pub struct AirGapStatus {
    pub score: f64,
    pub warnings: Vec<String>,
    pub is_air_gapped: bool,
}

/// Assess passphrase strength
#[must_use]
pub fn assess_passphrase_strength(passphrase: &str) -> PassphraseStrength {
    let mut score = 0.0;
    let mut issues = Vec::new();
    let mut recommendations = Vec::new();

    // Length check
    if passphrase.len() < 8 {
        issues.push("Passphrase is too short (minimum 8 characters recommended)".to_string());
    } else if passphrase.len() < 12 {
        score += 0.2;
        recommendations.push("Consider using a longer passphrase (12+ characters)".to_string());
    } else if passphrase.len() < 20 {
        score += 0.4;
    } else {
        score += 0.6;
    }

    // Character diversity
    let has_lower = passphrase.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = passphrase.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = passphrase.chars().any(|c| c.is_ascii_digit());
    let has_special = passphrase.chars().any(|c| !c.is_alphanumeric());

    let char_types = [has_lower, has_upper, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();
    score += (char_types as f64 / 4.0) * 0.3;

    if char_types < 3 {
        recommendations.push("Use a mix of uppercase, lowercase, numbers, and symbols".to_string());
    }

    // Common patterns check
    if is_common_pattern(passphrase) {
        issues.push("Contains common patterns or dictionary words".to_string());
        score *= 0.5;
    }

    // Entropy estimation
    let entropy = estimate_passphrase_entropy(passphrase);
    if entropy < 50.0 {
        issues.push(format!("Low entropy: {entropy:.1} bits"));
        score *= 0.7;
    } else if entropy > 80.0 {
        score += 0.1;
    }

    // Generate final recommendations
    if score < 0.3 {
        recommendations.push("🚨 Consider using a much stronger passphrase".to_string());
    } else if score < 0.6 {
        recommendations.push("⚠️  Passphrase strength could be improved".to_string());
    } else {
        recommendations.push("✅ Passphrase strength appears good".to_string());
    }

    if passphrase.is_empty() {
        recommendations
            .push("💡 Empty passphrase = no additional security beyond mnemonic".to_string());
    }

    PassphraseStrength {
        score,
        entropy,
        issues,
        recommendations,
    }
}

#[derive(Debug, Clone)]
pub struct PassphraseStrength {
    pub score: f64,
    pub entropy: f64,
    pub issues: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Check for common weak patterns
fn is_common_pattern(passphrase: &str) -> bool {
    let lower = passphrase.to_lowercase();

    // Common weak patterns
    let weak_patterns = [
        "password", "123456", "qwerty", "abc123", "admin", "user", "letmein", "welcome", "monkey",
        "dragon", "master", "shadow", "12345678", "football", "baseball", "superman", "batman",
    ];

    for pattern in &weak_patterns {
        if lower.contains(pattern) {
            return true;
        }
    }

    // Sequential characters
    if lower.contains("abcd") || lower.contains("1234") || lower.contains("qwer") {
        return true;
    }

    false
}

/// Estimate passphrase entropy (simplified)
fn estimate_passphrase_entropy(passphrase: &str) -> f64 {
    let mut charset_size = 0;

    if passphrase.chars().any(|c| c.is_ascii_lowercase()) {
        charset_size += 26;
    }
    if passphrase.chars().any(|c| c.is_ascii_uppercase()) {
        charset_size += 26;
    }
    if passphrase.chars().any(|c| c.is_ascii_digit()) {
        charset_size += 10;
    }
    if passphrase.chars().any(|c| !c.is_alphanumeric()) {
        charset_size += 32; // Approximation for special characters
    }

    if charset_size == 0 {
        return 0.0;
    }

    passphrase.len() as f64 * f64::from(charset_size).log2()
}
