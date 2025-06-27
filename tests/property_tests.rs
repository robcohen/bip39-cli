use bip39_cli::{
    cli::{LanguageOption, WordCount},
    security,
};
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_entropy_validation_always_works_for_valid_lengths(
        entropy_bytes in prop::collection::vec(any::<u8>(), 16..=32)
    ) {
        let hex_str = hex::encode(&entropy_bytes);

        // Only test valid lengths (16, 20, 24, 28, 32 bytes = 32, 40, 48, 56, 64 hex chars)
        let valid_lengths = [32, 40, 48, 56, 64];
        if valid_lengths.contains(&hex_str.len()) {
            prop_assert!(security::validate_entropy_hex(&hex_str).is_ok());
        }
    }

    #[test]
    fn test_word_count_conversion_consistency(word_count in 0u8..=4) {
        let word_counts = [
            WordCount::Twelve,
            WordCount::Fifteen,
            WordCount::Eighteen,
            WordCount::TwentyOne,
            WordCount::TwentyFour,
        ];

        if let Some(wc) = word_counts.get(word_count as usize) {
            let bits = wc.to_entropy_bits();
            let bytes = wc.to_entropy_bytes();
            let words = wc.to_word_count();

            // Verify relationships
            prop_assert_eq!(bytes * 8, bits);
            prop_assert!(words == 12 || words == 15 || words == 18 || words == 21 || words == 24);
            prop_assert!(bits == 128 || bits == 160 || bits == 192 || bits == 224 || bits == 256);
        }
    }

    #[test]
    fn test_mnemonic_word_count_validation(
        word_count in 1usize..50
    ) {
        let mnemonic = (0..word_count).map(|_| "word").collect::<Vec<_>>().join(" ");
        let result = security::validate_mnemonic_word_count(&mnemonic);

        let valid_counts = [12, 15, 18, 21, 24];
        if valid_counts.contains(&word_count) {
            prop_assert!(result.is_ok());
        } else {
            prop_assert!(result.is_err());
        }
    }

    #[test]
    fn test_hex_validation_rejects_non_hex(
        s in "[g-z]+"  // Generate strings with non-hex characters
    ) {
        // Pad to valid length but with invalid characters
        let padded = format!("{s:0<32}");
        prop_assert!(security::validate_entropy_hex(&padded).is_err());
    }

    #[test]
    fn test_hex_validation_accepts_valid_hex(
        hex_chars in prop::collection::vec(
            prop::char::range('0', 'f').prop_filter("valid hex", |c| c.is_ascii_hexdigit()),
            32..=64
        )
    ) {
        let hex_string: String = hex_chars.into_iter().collect();

        // Only test exact valid lengths
        let valid_lengths = [32, 40, 48, 56, 64];
        if valid_lengths.contains(&hex_string.len()) {
            prop_assert!(security::validate_entropy_hex(&hex_string).is_ok());
        }
    }

    #[test]
    fn test_language_conversion_is_consistent(lang_idx in 0usize..10) {
        let languages = [
            LanguageOption::English,
            LanguageOption::Japanese,
            LanguageOption::Korean,
            LanguageOption::Spanish,
            LanguageOption::ChineseSimplified,
            LanguageOption::ChineseTraditional,
            LanguageOption::French,
            LanguageOption::Italian,
            LanguageOption::Czech,
            LanguageOption::Portuguese,
        ];

        if let Some(lang_opt) = languages.get(lang_idx) {
            let bip39_lang: bip39::Language = (*lang_opt).into();

            // Just verify the conversion doesn't panic and produces a valid language
            prop_assert!(matches!(
                bip39_lang,
                bip39::Language::English |
                bip39::Language::Japanese |
                bip39::Language::Korean |
                bip39::Language::Spanish |
                bip39::Language::SimplifiedChinese |
                bip39::Language::TraditionalChinese |
                bip39::Language::French |
                bip39::Language::Italian |
                bip39::Language::Czech |
                bip39::Language::Portuguese
            ));
        }
    }

    #[test]
    fn test_edit_distance_properties(
        s1 in "[a-z]{1,10}",
        s2 in "[a-z]{1,10}"
    ) {
        let distance = bip39_cli::security::edit_distance(&s1, &s2);

        // Edit distance properties
        prop_assert!(distance <= s1.len().max(s2.len())); // Upper bound
        prop_assert_eq!(distance == 0, s1 == s2); // Zero iff equal

        // Symmetric property
        let reverse_distance = bip39_cli::security::edit_distance(&s2, &s1);
        prop_assert_eq!(distance, reverse_distance);
    }
}

// Unit tests using regular test framework for more specific scenarios
#[cfg(test)]
mod unit_property_tests {
    use bip39_cli::security;

    #[test]
    fn test_edit_distance_known_values() {
        assert_eq!(security::edit_distance("cat", "cat"), 0);
        assert_eq!(security::edit_distance("cat", "bat"), 1);
        assert_eq!(security::edit_distance("cat", "dog"), 3);
        assert_eq!(security::edit_distance("kitten", "sitting"), 3);
        assert_eq!(security::edit_distance("", "abc"), 3);
        assert_eq!(security::edit_distance("abc", ""), 3);
    }

    #[test]
    fn test_find_invalid_words_empty_suggestions() {
        let result =
            security::find_invalid_words("validword invalidword", bip39::Language::English);

        // Should find at least one invalid word (assuming these aren't in the word list)
        assert!(!result.is_empty());

        // Each invalid word should have position info
        for (position, word, _suggestions) in result {
            assert!(position > 0);
            assert!(!word.is_empty());
        }
    }

    #[test]
    fn test_entropy_validation_boundary_cases() {
        // Test exact boundary cases
        assert!(security::validate_entropy_hex("a".repeat(32).as_str()).is_ok()); // 32 chars
        assert!(security::validate_entropy_hex("a".repeat(31).as_str()).is_err()); // 31 chars
        assert!(security::validate_entropy_hex("a".repeat(33).as_str()).is_err()); // 33 chars

        assert!(security::validate_entropy_hex("a".repeat(64).as_str()).is_ok()); // 64 chars
        assert!(security::validate_entropy_hex("a".repeat(65).as_str()).is_err());
        // 65 chars
    }

    #[test]
    fn test_word_count_validation_boundary_cases() {
        // Test exact boundary cases
        assert!(security::validate_mnemonic_word_count("word ".repeat(12).trim()).is_ok());
        assert!(security::validate_mnemonic_word_count("word ".repeat(11).trim()).is_err());
        assert!(security::validate_mnemonic_word_count("word ".repeat(13).trim()).is_err());

        assert!(security::validate_mnemonic_word_count("word ".repeat(24).trim()).is_ok());
        assert!(security::validate_mnemonic_word_count("word ".repeat(25).trim()).is_err());
    }
}
