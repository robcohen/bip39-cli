use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_cli_generate_12_words() {
    let mut cmd = Command::cargo_bin("bip39").unwrap();
    cmd.args(&["generate", "--words", "12", "--quiet"]);

    let output = cmd.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let mnemonic = stdout.trim();

    // Should have exactly 12 words
    assert_eq!(mnemonic.split_whitespace().count(), 12);

    // Should not be empty
    assert!(!mnemonic.is_empty());
}

#[test]
fn test_cli_generate_24_words() {
    let mut cmd = Command::cargo_bin("bip39").unwrap();
    cmd.args(&["generate", "--words", "24", "--quiet"]);

    let output = cmd.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let mnemonic = stdout.trim();

    // Should have exactly 24 words
    assert_eq!(mnemonic.split_whitespace().count(), 24);
}

#[test]
fn test_cli_generate_with_entropy_and_seed() {
    let mut cmd = Command::cargo_bin("bip39").unwrap();
    cmd.args(&[
        "generate",
        "--words",
        "12",
        "--show-entropy",
        "--show-seed",
        "--quiet",
    ]);

    let output = cmd.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.trim().split('\n').collect();

    // Should have 3 lines: mnemonic, empty line, entropy, empty line, seed
    assert!(lines.len() >= 3);

    // Find the lines with actual content (non-empty)
    let content_lines: Vec<&str> = lines
        .iter()
        .filter(|&line| !line.is_empty())
        .copied()
        .collect();
    assert_eq!(content_lines.len(), 3);

    // Mnemonic should be 12 words
    assert_eq!(content_lines[0].split_whitespace().count(), 12);

    // Entropy should be 32 hex chars (16 bytes * 2)
    assert_eq!(content_lines[1].len(), 32);
    assert!(content_lines[1].chars().all(|c| c.is_ascii_hexdigit()));

    // Seed should be 128 hex chars (64 bytes * 2)
    assert_eq!(content_lines[2].len(), 128);
    assert!(content_lines[2].chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_cli_validate_valid_mnemonic() {
    let mut cmd = Command::cargo_bin("bip39").unwrap();
    cmd.args(&[
        "validate",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "--quiet"
    ]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("valid"));
}

#[test]
fn test_cli_validate_invalid_mnemonic() {
    let mut cmd = Command::cargo_bin("bip39").unwrap();
    cmd.args(&[
        "validate",
        "invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid",
        "--quiet"
    ]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Invalid word"));
}

#[test]
fn test_cli_validate_wrong_word_count() {
    let mut cmd = Command::cargo_bin("bip39").unwrap();
    cmd.args(&["validate", "abandon abandon abandon", "--quiet"]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Invalid mnemonic word count: 3"));
}

#[test]
fn test_cli_seed_generation() {
    let mut cmd = Command::cargo_bin("bip39").unwrap();
    cmd.args(&[
        "seed",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "--quiet"
    ]);

    let output = cmd.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let seed = stdout.trim();

    // Seed should be 128 hex chars (64 bytes * 2)
    assert_eq!(seed.len(), 128);
    assert!(seed.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_cli_seed_with_passphrase() {
    let mut cmd = Command::cargo_bin("bip39").unwrap();
    cmd.args(&[
        "seed",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "--passphrase", "test",
        "--quiet"
    ]);

    let output = cmd.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let seed_with_passphrase = stdout.trim();

    // Generate seed without passphrase
    let mut cmd2 = Command::cargo_bin("bip39").unwrap();
    cmd2.args(&[
        "seed",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "--quiet"
    ]);

    let output2 = cmd2.assert().success();
    let stdout2 = String::from_utf8(output2.get_output().stdout.clone()).unwrap();
    let seed_without_passphrase = stdout2.trim();

    // Seeds should be different
    assert_ne!(seed_with_passphrase, seed_without_passphrase);
}

#[test]
fn test_cli_from_entropy() {
    let mut cmd = Command::cargo_bin("bip39").unwrap();
    cmd.args(&[
        "from-entropy",
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        "--quiet",
    ]);

    let output = cmd.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let mnemonic = stdout.trim();

    // Should generate exactly 12 words (128 bits)
    assert_eq!(mnemonic.split_whitespace().count(), 12);
}

#[test]
fn test_cli_from_entropy_invalid_length() {
    let mut cmd = Command::cargo_bin("bip39").unwrap();
    cmd.args(&[
        "from-entropy",
        "a0a1a2a3", // Too short
        "--quiet",
    ]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Invalid entropy length"));
}

#[test]
fn test_cli_from_entropy_invalid_hex() {
    let mut cmd = Command::cargo_bin("bip39").unwrap();
    cmd.args(&[
        "from-entropy",
        "g0a1a2a3a4a5a6a7a8a9aaabacadaeaf", // 'g' is not valid hex
        "--quiet",
    ]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Error at position: 0"));
}

#[test]
fn test_cli_extract_entropy() {
    let mut cmd = Command::cargo_bin("bip39").unwrap();
    cmd.args(&[
        "entropy",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "--quiet"
    ]);

    let output = cmd.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let entropy = stdout.trim();

    // Should be 32 hex chars for 12 words (16 bytes * 2)
    assert_eq!(entropy.len(), 32);
    assert!(entropy.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_cli_roundtrip_entropy_mnemonic() {
    // Generate entropy -> mnemonic -> entropy should be consistent
    let original_entropy = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";

    // Convert entropy to mnemonic
    let mut cmd1 = Command::cargo_bin("bip39").unwrap();
    cmd1.args(&["from-entropy", original_entropy, "--quiet"]);

    let output1 = cmd1.assert().success();
    let mnemonic = String::from_utf8(output1.get_output().stdout.clone()).unwrap();
    let mnemonic = mnemonic.trim();

    // Convert mnemonic back to entropy
    let mut cmd2 = Command::cargo_bin("bip39").unwrap();
    cmd2.args(&["entropy", mnemonic, "--quiet"]);

    let output2 = cmd2.assert().success();
    let extracted_entropy = String::from_utf8(output2.get_output().stdout.clone()).unwrap();
    let extracted_entropy = extracted_entropy.trim();

    // Should match original entropy
    assert_eq!(original_entropy, extracted_entropy);
}

#[test]
fn test_cli_shell_completion() {
    let mut cmd = Command::cargo_bin("bip39").unwrap();
    cmd.args(&["--generate", "bash"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("_bip39"));
}

#[test]
fn test_cli_help() {
    let mut cmd = Command::cargo_bin("bip39").unwrap();
    cmd.args(&["--help"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("BIP39 mnemonic operations"));
}

#[test]
fn test_cli_version() {
    let mut cmd = Command::cargo_bin("bip39").unwrap();
    cmd.args(&["--version"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("0.1.0"));
}

#[test]
fn test_cli_no_command() {
    let mut cmd = Command::cargo_bin("bip39").unwrap();

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("No command provided"));
}

#[test]
fn test_cli_different_languages() {
    for language in &["english", "japanese", "spanish", "french"] {
        let mut cmd = Command::cargo_bin("bip39").unwrap();
        cmd.args(&[
            "generate",
            "--words",
            "12",
            "--language",
            language,
            "--quiet",
        ]);

        let output = cmd.assert().success();
        let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
        let mnemonic = stdout.trim();

        // Should generate 12 words regardless of language
        assert_eq!(mnemonic.split_whitespace().count(), 12);
    }
}
