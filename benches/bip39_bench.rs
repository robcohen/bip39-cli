use bip39::{Language, Mnemonic};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{rngs::OsRng, RngCore};

fn bench_generate_mnemonic(c: &mut Criterion) {
    let mut group = c.benchmark_group("generate_mnemonic");

    for &word_count in &[12, 15, 18, 21, 24] {
        let entropy_bytes = word_count * 32 / 24; // Convert word count to entropy bytes

        group.bench_function(format!("{}_words", word_count), |b| {
            b.iter(|| {
                let mut entropy = vec![0u8; entropy_bytes];
                OsRng.fill_bytes(&mut entropy);
                black_box(Mnemonic::from_entropy_in(Language::English, &entropy).unwrap());
            })
        });
    }

    group.finish();
}

fn bench_validate_mnemonic(c: &mut Criterion) {
    let test_mnemonics = [
        ("12_words", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
        ("15_words", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
        ("18_words", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent"),
        ("21_words", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
        ("24_words", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"),
    ];

    let mut group = c.benchmark_group("validate_mnemonic");

    for (name, mnemonic) in &test_mnemonics {
        group.bench_function(*name, |b| {
            b.iter(|| {
                black_box(Mnemonic::parse_in_normalized(Language::English, mnemonic).unwrap());
            })
        });
    }

    group.finish();
}

fn bench_mnemonic_to_seed(c: &mut Criterion) {
    let mnemonic = Mnemonic::parse_in_normalized(
        Language::English,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    ).unwrap();

    c.bench_function("mnemonic_to_seed", |b| {
        b.iter(|| {
            black_box(mnemonic.to_seed(""));
        })
    });

    c.bench_function("mnemonic_to_seed_with_passphrase", |b| {
        b.iter(|| {
            black_box(mnemonic.to_seed("test_passphrase"));
        })
    });
}

fn bench_entropy_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("entropy_operations");

    // Test entropy to mnemonic conversion
    let entropy_32 = vec![0xab; 32]; // 256 bits for 24 words
    group.bench_function("entropy_to_mnemonic_24_words", |b| {
        b.iter(|| {
            black_box(Mnemonic::from_entropy_in(Language::English, &entropy_32).unwrap());
        })
    });

    // Test mnemonic to entropy conversion
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy_32).unwrap();
    group.bench_function("mnemonic_to_entropy", |b| {
        b.iter(|| {
            black_box(mnemonic.to_entropy());
        })
    });

    group.finish();
}

fn bench_languages(c: &mut Criterion) {
    let entropy = vec![0xab; 16]; // 128 bits for 12 words
    let languages = [
        Language::English,
        Language::Japanese,
        Language::Korean,
        Language::Spanish,
        Language::SimplifiedChinese,
        Language::TraditionalChinese,
        Language::French,
        Language::Italian,
        Language::Czech,
        Language::Portuguese,
    ];

    let mut group = c.benchmark_group("languages");

    for language in &languages {
        let lang_name = format!("{:?}", language).to_lowercase();
        group.bench_function(format!("generate_{}", lang_name), |b| {
            b.iter(|| {
                black_box(Mnemonic::from_entropy_in(*language, &entropy).unwrap());
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_generate_mnemonic,
    bench_validate_mnemonic,
    bench_mnemonic_to_seed,
    bench_entropy_operations,
    bench_languages
);
criterion_main!(benches);
