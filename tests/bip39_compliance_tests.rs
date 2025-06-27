/// BIP39 compliance tests using official test vectors
/// Reads test vectors from the official Trezor vectors.json file
use serde_json::Value;

#[derive(Debug, Clone)]
struct TestVector {
    entropy: String,
    mnemonic: String,
    seed: String,
}

fn load_test_vectors() -> Result<Vec<TestVector>, Box<dyn std::error::Error>> {
    let vectors_json = include_str!("../test-vectors.json");
    let data: Value = serde_json::from_str(vectors_json)?;

    let english_vectors = data["english"]
        .as_array()
        .ok_or("Missing english vectors")?;

    let mut vectors = Vec::new();
    for vector in english_vectors {
        let array = vector.as_array().ok_or("Invalid vector format")?;
        if array.len() >= 4 {
            vectors.push(TestVector {
                entropy: array[0].as_str().unwrap_or("").to_string(),
                mnemonic: array[1].as_str().unwrap_or("").to_string(),
                seed: array[2].as_str().unwrap_or("").to_string(),
            });
        }
    }

    Ok(vectors)
}

/// Validate a test vector against our implementation
/// Note: BIP39 vectors use "TREZOR" as passphrase for seed derivation
fn validate_test_vector(vector: &TestVector) -> Result<(), String> {
    use bip39::Mnemonic;

    // 1. Test entropy -> mnemonic conversion
    let entropy_bytes =
        hex::decode(&vector.entropy).map_err(|e| format!("Failed to decode entropy: {}", e))?;

    let generated_mnemonic = Mnemonic::from_entropy(&entropy_bytes)
        .map_err(|e| format!("Failed to generate mnemonic from entropy: {}", e))?;

    if generated_mnemonic.to_string() != vector.mnemonic {
        return Err(format!(
            "Mnemonic mismatch!\nExpected: {}\nGenerated: {}",
            vector.mnemonic, generated_mnemonic
        ));
    }

    // 2. Test mnemonic -> seed conversion with "TREZOR" passphrase
    let parsed_mnemonic = Mnemonic::parse(&vector.mnemonic)
        .map_err(|e| format!("Failed to parse mnemonic: {}", e))?;

    let generated_seed = parsed_mnemonic.to_seed("TREZOR");
    let generated_seed_hex = hex::encode(generated_seed);

    if generated_seed_hex != vector.seed {
        return Err(format!(
            "Seed mismatch!\nExpected: {}\nGenerated: {}",
            vector.seed, generated_seed_hex
        ));
    }

    // 3. Test mnemonic -> entropy conversion (round trip)
    let extracted_entropy = parsed_mnemonic.to_entropy();
    let extracted_entropy_hex = hex::encode(extracted_entropy);

    if extracted_entropy_hex != vector.entropy {
        return Err(format!(
            "Entropy round-trip failed!\nOriginal: {}\nExtracted: {}",
            vector.entropy, extracted_entropy_hex
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_vectors() {
        let vectors = load_test_vectors().expect("Should load test vectors");
        assert_eq!(vectors.len(), 24, "Should have 24 English test vectors");

        // Check first vector
        assert_eq!(vectors[0].entropy, "00000000000000000000000000000000");
        assert_eq!(vectors[0].mnemonic, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");

        // Check that we have different entropy lengths
        let entropy_lengths: std::collections::HashSet<_> =
            vectors.iter().map(|v| v.entropy.len()).collect();
        assert!(
            entropy_lengths.len() > 1,
            "Should have multiple entropy lengths"
        );
    }

    #[test]
    fn test_bip39_vector_1_all_zeros() {
        let vectors = load_test_vectors().expect("Should load test vectors");
        validate_test_vector(&vectors[0]).expect("Vector 1 should pass");
    }

    #[test]
    fn test_bip39_vector_2_legal_winner() {
        let vectors = load_test_vectors().expect("Should load test vectors");
        validate_test_vector(&vectors[1]).expect("Vector 2 should pass");
    }

    #[test]
    fn test_bip39_vector_3_letter_advice() {
        let vectors = load_test_vectors().expect("Should load test vectors");
        validate_test_vector(&vectors[2]).expect("Vector 3 should pass");
    }

    #[test]
    fn test_bip39_vector_4_all_ones() {
        let vectors = load_test_vectors().expect("Should load test vectors");
        validate_test_vector(&vectors[3]).expect("Vector 4 should pass");
    }

    #[test]
    fn test_all_24_bip39_vectors() {
        let vectors = load_test_vectors().expect("Should load test vectors");

        for (i, vector) in vectors.iter().enumerate() {
            validate_test_vector(vector)
                .unwrap_or_else(|e| panic!("BIP39 test vector {} failed: {}", i + 1, e));
        }

        println!("✅ All {} BIP39 test vectors passed!", vectors.len());
    }

    #[test]
    fn test_entropy_to_mnemonic_deterministic() {
        use bip39::Mnemonic;

        // Test that same entropy always produces same mnemonic
        let test_entropy = "deadbeefdeadbeefdeadbeefdeadbeef";
        let entropy_bytes = hex::decode(test_entropy).unwrap();

        let mnemonic1 = Mnemonic::from_entropy(&entropy_bytes).unwrap();
        let mnemonic2 = Mnemonic::from_entropy(&entropy_bytes).unwrap();

        assert_eq!(
            mnemonic1.to_string(),
            mnemonic2.to_string(),
            "Same entropy should always produce same mnemonic"
        );
    }

    #[test]
    fn test_mnemonic_to_seed_deterministic() {
        use bip39::Mnemonic;

        // Test that same mnemonic+passphrase always produces same seed
        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase = "TREZOR";

        let mnemonic = Mnemonic::parse(mnemonic_str).unwrap();
        let seed1 = mnemonic.to_seed(passphrase);
        let seed2 = mnemonic.to_seed(passphrase);

        assert_eq!(
            seed1, seed2,
            "Same mnemonic and passphrase should always produce same seed"
        );
    }

    #[test]
    fn test_round_trip_entropy_mnemonic_entropy() {
        use bip39::Mnemonic;

        // Test various entropy sizes
        let test_entropies = [
            "deadbeefdeadbeefdeadbeefdeadbeef",                 // 128 bits
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",         // 160 bits
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", // 192 bits
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", // 224 bits
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", // 256 bits
        ];

        for test_entropy in &test_entropies {
            let entropy_bytes = hex::decode(test_entropy).unwrap();
            let mnemonic = Mnemonic::from_entropy(&entropy_bytes).unwrap();
            let recovered_entropy = mnemonic.to_entropy();
            let recovered_entropy_hex = hex::encode(recovered_entropy);

            assert_eq!(
                *test_entropy, recovered_entropy_hex,
                "Entropy round-trip failed for {}",
                test_entropy
            );
        }
    }

    #[test]
    fn test_coverage_of_all_entropy_sizes() {
        let vectors = load_test_vectors().expect("Should load test vectors");

        // Group vectors by entropy length to verify we test all BIP39 sizes
        let mut entropy_lengths = std::collections::HashMap::new();
        for vector in &vectors {
            let length = vector.entropy.len() / 2; // hex chars to bytes
            *entropy_lengths.entry(length).or_insert(0) += 1;
        }

        println!("Entropy size coverage:");
        for (bytes, count) in &entropy_lengths {
            let bits = bytes * 8;
            let words = (bits * 3) / 32;
            println!(
                "  {} bytes ({} bits, {} words): {} vectors",
                bytes, bits, words, count
            );
        }

        // Ensure we have vectors for the entropy sizes in the official test vectors
        assert!(
            entropy_lengths.contains_key(&16),
            "Should have 128-bit vectors"
        );
        assert!(
            entropy_lengths.contains_key(&24),
            "Should have 192-bit vectors"
        );
        assert!(
            entropy_lengths.contains_key(&32),
            "Should have 256-bit vectors"
        );

        // Note: Official BIP39 vectors don't include 160-bit and 224-bit cases
        // but our implementation should still support them
    }
}
