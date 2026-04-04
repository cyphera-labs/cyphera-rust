//! Cross-language compatibility tests.
//!
//! Reads vectors from tests/vectors/cross-language.json and verifies
//! the Rust implementation produces identical results.
//! The same JSON file is consumed by Go, Python, etc.

use cyphera::Client;
use cyphera::keys::{MemoryProvider, KeyRecord, KeyStatus};
use cyphera::policy::{PolicyFile, PolicyEntry};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    engine: String,
    #[serde(default)]
    alphabet: Option<String>,
    #[serde(default)]
    key_hex: Option<String>,
    #[serde(default)]
    tweak_hex: Option<String>,
    #[serde(default)]
    plaintext: Option<String>,
    #[serde(default)]
    plaintext_formatted: Option<String>,
    #[serde(default)]
    ciphertext: Option<String>,
    #[serde(default)]
    output: Option<String>,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    test_type: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

fn load_vectors() -> VectorFile {
    let data = std::fs::read_to_string("../../tests/vectors/cross-language.json")
        .expect("failed to read cross-language.json");
    serde_json::from_str(&data).expect("failed to parse cross-language.json")
}

fn make_client(v: &Vector) -> Client {
    let key = v.key_hex.as_ref()
        .map(|h| hex::decode(h).unwrap())
        .unwrap_or_default();
    let tweak = v.tweak_hex.as_ref()
        .map(|h| hex::decode(h).unwrap())
        .unwrap_or_default();

    let mut policies = HashMap::new();
    policies.insert("test".to_string(), PolicyEntry {
        engine: v.engine.clone(),
        alphabet: v.alphabet.clone(),
        key_ref: Some("key".to_string()),
        tag: None,
        mode: None,
    });

    let provider = MemoryProvider::new(vec![
        KeyRecord {
            key_ref: "key".into(),
            version: 1,
            status: KeyStatus::Active,
            material: key,
            tweak,
        },
    ]);

    Client::from_policy(
        PolicyFile { policies },
        Box::new(provider),
    )
}

#[test]
fn cross_language_vectors() {
    let vf = load_vectors();
    let mut passed = 0;
    let mut total = 0;

    for v in &vf.vectors {
        let test_type = v.test_type.as_deref().unwrap_or("exact");

        match test_type {
            "exact" | "" => {
                // Exact ciphertext match + roundtrip
                total += 1;
                let client = make_client(v);
                let pt = v.plaintext.as_ref().unwrap();
                let expected_ct = v.ciphertext.as_ref().unwrap();

                let ct = client.encrypt("test", pt)
                    .unwrap_or_else(|e| panic!("[{}] encrypt failed: {e}", v.name));
                assert_eq!(&ct.output, expected_ct,
                    "[{}] ciphertext mismatch: got '{}', expected '{expected_ct}'", v.name, ct.output);

                let decrypted = client.decrypt("test", &ct.output)
                    .unwrap_or_else(|e| panic!("[{}] decrypt failed: {e}", v.name));
                assert_eq!(&decrypted.output, pt,
                    "[{}] roundtrip failed", v.name);

                passed += 1;
            }

            "roundtrip_format" => {
                // Format preservation: encrypt formatted input, verify structure preserved, roundtrip
                total += 1;
                let client = make_client(v);
                let formatted = v.plaintext_formatted.as_ref().unwrap();

                let ct = client.encrypt("test", formatted)
                    .unwrap_or_else(|e| panic!("[{}] encrypt failed: {e}", v.name));

                // Verify structural chars preserved
                for (i, (orig, enc)) in formatted.chars().zip(ct.output.chars()).enumerate() {
                    if !orig.is_alphanumeric() {
                        assert_eq!(orig, enc,
                            "[{}] structural char at pos {i} not preserved: expected '{orig}', got '{enc}'",
                            v.name);
                    }
                }

                // Roundtrip
                let decrypted = client.decrypt("test", &ct.output)
                    .unwrap_or_else(|e| panic!("[{}] decrypt failed: {e}", v.name));
                assert_eq!(&decrypted.output, formatted,
                    "[{}] roundtrip failed: got '{}', expected '{formatted}'", v.name, decrypted.output);

                passed += 1;
            }

            "mask" => {
                total += 1;
                let client = make_client(v);
                let pt = v.plaintext.as_ref().unwrap();
                let pattern = v.pattern.as_ref().unwrap();
                let expected = v.output.as_ref().unwrap();

                let result = client.mask(pt, pattern)
                    .unwrap_or_else(|e| panic!("[{}] mask failed: {e}", v.name));
                assert_eq!(&result.output, expected,
                    "[{}] mask mismatch: got '{}', expected '{expected}'", v.name, result.output);

                passed += 1;
            }

            "hash_deterministic" => {
                total += 1;
                let client = make_client(v);
                let pt = v.plaintext.as_ref().unwrap();

                let h1 = client.hash("test", pt)
                    .unwrap_or_else(|e| panic!("[{}] hash failed: {e}", v.name));
                let h2 = client.hash("test", pt)
                    .unwrap_or_else(|e| panic!("[{}] hash failed: {e}", v.name));
                assert_eq!(h1.output, h2.output,
                    "[{}] hash not deterministic", v.name);
                assert!(!h1.output.is_empty(), "[{}] hash output empty", v.name);

                passed += 1;
            }

            other => {
                panic!("Unknown test_type: {other}");
            }
        }
    }

    println!("\nCross-language vectors: {passed}/{total} passed");
    assert_eq!(passed, total);
}
