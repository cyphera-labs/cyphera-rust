//! Bridge between `keychain` (universal key resolution) and `cyphera-keys` (KeyProvider trait).
//!
//! This lets you use keychain URIs directly in policy files:
//!
//! ```yaml
//! policies:
//!   ssn-east:
//!     engine: ff1
//!     key_ref: "aws-kms://arn:aws:kms:us-east-1:123:key/ssn"
//!   ssn-dev:
//!     engine: ff1
//!     key_ref: "env://DEV_KEY?hex"
//! ```
//!
//! The `key_ref` IS the keychain URI. Different policies can use different
//! providers, regions, and keys — all resolved at runtime.

use cyphera_keys::{KeyProvider, KeyRecord, KeyError, KeyStatus};
use keychain::{KeyStore, KeychainError};
use std::collections::HashMap;
use std::sync::RwLock;

/// A KeyProvider backed by a keychain KeyStore.
/// Resolves key_ref values as keychain URIs.
pub struct KeychainProvider {
    store: KeyStore,
    tweak_default: Vec<u8>,
    // Simple cache: URI → resolved key material
    cache: RwLock<HashMap<String, Vec<u8>>>,
}

impl KeychainProvider {
    /// Create a new KeychainProvider wrapping a keychain KeyStore.
    ///
    /// `tweak_default` is used as the tweak for all resolved keys.
    /// For per-key tweaks, derive them from the URI or key metadata.
    pub fn new(store: KeyStore, tweak_default: Vec<u8>) -> Self {
        Self {
            store,
            tweak_default,
            cache: RwLock::new(HashMap::new()),
        }
    }

    fn resolve_uri(&self, uri: &str) -> Result<Vec<u8>, KeyError> {
        // Check cache first
        if let Ok(cache) = self.cache.read() {
            if let Some(material) = cache.get(uri) {
                return Ok(material.clone());
            }
        }

        // Resolve via keychain
        let resolved = self.store.resolve(uri).map_err(|e| match e {
            KeychainError::NotFound(msg) => KeyError::NotFound(msg),
            other => KeyError::NotFound(other.to_string()),
        })?;

        // Cache it
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(uri.to_string(), resolved.material.clone());
        }

        Ok(resolved.material)
    }
}

impl KeyProvider for KeychainProvider {
    fn resolve(&self, key_ref: &str) -> Result<KeyRecord, KeyError> {
        let material = self.resolve_uri(key_ref)?;

        Ok(KeyRecord {
            key_ref: key_ref.to_string(),
            version: 1,
            status: KeyStatus::Active,
            material,
            tweak: self.tweak_default.clone(),
        })
    }

    fn resolve_version(&self, key_ref: &str, _version: u32) -> Result<KeyRecord, KeyError> {
        // Keychain doesn't have versioning — always resolves current.
        // For versioned keys, the URI itself should include version info,
        // or use a backend that supports it (Vault, KMS key aliases).
        self.resolve(key_ref)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keychain::{KeyBackend, ResolvedKey};

    /// Test backend that returns a fixed key
    struct FixedBackend {
        material: Vec<u8>,
    }

    impl KeyBackend for FixedBackend {
        fn scheme(&self) -> &str { "test" }
        fn resolve(&self, path: &str) -> Result<ResolvedKey, KeychainError> {
            Ok(ResolvedKey {
                uri: format!("test://{path}"),
                material: self.material.clone(),
                metadata: HashMap::new(),
            })
        }
    }

    #[test]
    fn test_keychain_provider_resolves() {
        let store = KeyStore::new()
            .register(Box::new(FixedBackend {
                material: vec![0xAB; 32],
            }));

        let provider = KeychainProvider::new(store, vec![0u8; 8]);
        let record = provider.resolve("test://my-key").unwrap();

        assert_eq!(record.material, vec![0xAB; 32]);
        assert_eq!(record.key_ref, "test://my-key");
        assert_eq!(record.status, KeyStatus::Active);
    }

    #[test]
    fn test_keychain_provider_caches() {
        let store = KeyStore::new()
            .register(Box::new(FixedBackend {
                material: vec![0xCD; 16],
            }));

        let provider = KeychainProvider::new(store, vec![0u8; 8]);

        // First resolve
        let r1 = provider.resolve("test://cached-key").unwrap();
        // Second resolve (hits cache)
        let r2 = provider.resolve("test://cached-key").unwrap();

        assert_eq!(r1.material, r2.material);
    }

    #[test]
    fn test_keychain_provider_unknown_scheme_errors() {
        let store = KeyStore::new(); // no backends registered
        let provider = KeychainProvider::new(store, vec![0u8; 8]);

        let result = provider.resolve("nope://key");
        assert!(result.is_err());
    }

    #[test]
    fn test_full_flow_with_cyphera_client() {
        use crate::Client;

        let store = KeyStore::new()
            .register(Box::new(FixedBackend {
                material: vec![0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                               0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C],
            }));

        let provider = KeychainProvider::new(store, vec![0u8; 8]);

        let yaml = r#"
policies:
  ssn:
    engine: ff1
    key_ref: "test://ssn-key"
"#;
        let pf = cyphera_policy::PolicyFile::from_yaml(yaml).unwrap();
        let client = Client::from_policy(pf, Box::new(provider));

        // Encrypt using keychain-resolved key
        let ct = client.encrypt("ssn", "123-45-6789").unwrap();
        assert_ne!(ct.output, "123-45-6789");
        assert_eq!(ct.output.matches('-').count(), 2);

        // Decrypt
        let pt = client.decrypt("ssn", &ct.output).unwrap();
        assert_eq!(pt.output, "123-45-6789");
    }
}
