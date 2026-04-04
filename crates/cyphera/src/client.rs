use cyphera_alphabet::{self, Alphabet};
use cyphera_audit::{AuditEvent, AuditLogger, NoopLogger};
use cyphera_keys::{KeyProvider, KeyRecord, MemoryProvider, KeyStatus};
use cyphera_policy::{PolicyFile, PolicyEntry};
use thiserror::Error;
use std::collections::HashMap;
use std::sync::Arc;

use crate::format;

#[derive(Error, Debug)]
pub enum CypheraError {
    #[error("policy not found: {0}")]
    PolicyNotFound(String),
    #[error("key error: {0}")]
    Key(#[from] cyphera_keys::KeyError),
    #[error("policy error: {0}")]
    Policy(#[from] cyphera_policy::PolicyError),
    #[error("ff1 error: {0}")]
    FF1(#[from] cyphera_ff1::FF1Error),
    #[error("ff3 error: {0}")]
    FF3(#[from] cyphera_ff3::FF3Error),
    #[error("unknown engine: {0}")]
    UnknownEngine(String),
    #[error("input too short for masking")]
    MaskInputTooShort,
    #[error("hash error: {0}")]
    Hash(#[from] cyphera_hash::HashError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type alias for Cyphera operations
pub type Result<T> = std::result::Result<T, CypheraError>;

/// The output of an encrypt/decrypt/mask/hash operation
#[derive(Debug, Clone)]
pub struct ProtectResult {
    pub output: String,
    pub policy_name: String,
    pub engine: String,
    pub key_ref: Option<String>,
    pub key_version: Option<u32>,
    pub reversible: bool,
}

/// The main Cyphera client. This is what developers use.
pub struct Client {
    policies: HashMap<String, PolicyEntry>,
    key_provider: Arc<dyn KeyProvider>,
    logger: Arc<dyn AuditLogger>,
    default_key_ref: Option<String>,
}

impl Client {
    /// Create a client from a YAML policy file on disk
    pub fn from_policy_file(
        path: &str,
        key_provider: Box<dyn KeyProvider>,
    ) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let pf = PolicyFile::from_yaml(&contents)?;
        Ok(Self {
            policies: pf.policies,
            key_provider: Arc::from(key_provider),
            logger: Arc::new(NoopLogger),
            default_key_ref: None,
        })
    }

    /// Create a client from a PolicyFile struct
    pub fn from_policy(
        policy: PolicyFile,
        key_provider: Box<dyn KeyProvider>,
    ) -> Self {
        Self {
            policies: policy.policies,
            key_provider: Arc::from(key_provider),
            logger: Arc::new(NoopLogger),
            default_key_ref: None,
        }
    }

    /// Quick start: create a client with a raw key and built-in presets.
    /// Uses FF1 + alphanumeric for all presets.
    pub fn with_defaults(key: &[u8], tweak: &[u8]) -> Self {
        let key_ref = "default".to_string();
        let provider = MemoryProvider::new(vec![
            KeyRecord {
                key_ref: key_ref.clone(),
                version: 1,
                status: KeyStatus::Active,
                material: key.to_vec(),
                tweak: tweak.to_vec(),
            },
        ]);

        let mut policies = HashMap::new();
        // Built-in presets — all use ff1 + alphanumeric + default key
        for name in &["ssn", "card", "pan", "phone", "dob", "name", "address", "general"] {
            policies.insert(name.to_string(), PolicyEntry {
                engine: "ff1".to_string(),
                alphabet: Some("alphanumeric".to_string()),
                key_ref: Some(key_ref.clone()),
                tag: None,
                mode: None,
            });
        }

        Self {
            policies,
            key_provider: Arc::new(provider),
            logger: Arc::new(NoopLogger),
            default_key_ref: Some(key_ref),
        }
    }

    /// Use the builder for full control
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    // ── Public API ──────────────────────────────────────────────────────

    /// Encrypt a value using the named policy.
    /// Structural characters (dashes, slashes, etc.) are preserved.
    pub fn encrypt(&self, policy_name: &str, plaintext: &str) -> Result<ProtectResult> {
        let policy = self.get_policy(policy_name)?;
        let alphabet = self.resolve_alphabet(&policy);
        let key = self.resolve_key(&policy)?;

        // Extract encryptable chars, preserving structure
        let (extracted, template) = format::extract(plaintext, &alphabet);

        // Encrypt the extracted portion
        let encrypted = match policy.engine.as_str() {
            "ff1" => {
                let cipher = cyphera_ff1::FF1::new(&key.material, &key.tweak, alphabet)?;
                cipher.encrypt(&extracted)?
            }
            "ff3" => {
                let cipher = cyphera_ff3::FF3::new(&key.material, &key.tweak, alphabet)?;
                cipher.encrypt(&extracted)?
            }
            engine => return Err(CypheraError::UnknownEngine(engine.to_string())),
        };

        // Reconstruct with structural chars
        let output = format::reconstruct(&encrypted, &template);

        self.log_event(policy_name, "encrypt", &policy.engine, &key, true);

        Ok(ProtectResult {
            output,
            policy_name: policy_name.to_string(),
            engine: policy.engine.clone(),
            key_ref: Some(key.key_ref.clone()),
            key_version: Some(key.version),
            reversible: true,
        })
    }

    /// Decrypt a value using the named policy.
    pub fn decrypt(&self, policy_name: &str, ciphertext: &str) -> Result<ProtectResult> {
        let policy = self.get_policy(policy_name)?;
        let alphabet = self.resolve_alphabet(&policy);
        let key = self.resolve_key(&policy)?;

        let (extracted, template) = format::extract(ciphertext, &alphabet);

        let decrypted = match policy.engine.as_str() {
            "ff1" => {
                let cipher = cyphera_ff1::FF1::new(&key.material, &key.tweak, alphabet)?;
                cipher.decrypt(&extracted)?
            }
            "ff3" => {
                let cipher = cyphera_ff3::FF3::new(&key.material, &key.tweak, alphabet)?;
                cipher.decrypt(&extracted)?
            }
            engine => return Err(CypheraError::UnknownEngine(engine.to_string())),
        };

        let output = format::reconstruct(&decrypted, &template);

        self.log_event(policy_name, "decrypt", &policy.engine, &key, true);

        Ok(ProtectResult {
            output,
            policy_name: policy_name.to_string(),
            engine: policy.engine.clone(),
            key_ref: Some(key.key_ref.clone()),
            key_version: Some(key.version),
            reversible: true,
        })
    }

    /// Mask a value — irreversible.
    pub fn mask(&self, plaintext: &str, pattern: &str) -> Result<ProtectResult> {
        let output = match pattern {
            "last4" | "last_4" => cyphera_mask::last_n(plaintext, 4, '*'),
            "last6" | "last_6" => cyphera_mask::last_n(plaintext, 6, '*'),
            "first4" | "first_4" => cyphera_mask::first_n(plaintext, 4, '*'),
            "first6" | "first_6" => cyphera_mask::first_n(plaintext, 6, '*'),
            "full" => cyphera_mask::full(plaintext, '*'),
            _ => cyphera_mask::full(plaintext, '*'),
        };

        Ok(ProtectResult {
            output,
            policy_name: "mask".to_string(),
            engine: "mask".to_string(),
            key_ref: None,
            key_version: None,
            reversible: false,
        })
    }

    /// Hash a value — irreversible, deterministic.
    pub fn hash(&self, policy_name: &str, plaintext: &str) -> Result<ProtectResult> {
        let policy = self.get_policy(policy_name)?;
        let key = self.resolve_key(&policy)?;

        let output = cyphera_hash::hmac_sha256(&key.material, plaintext)?;

        Ok(ProtectResult {
            output,
            policy_name: policy_name.to_string(),
            engine: "hash".to_string(),
            key_ref: Some(key.key_ref.clone()),
            key_version: Some(key.version),
            reversible: false,
        })
    }

    // ── Generic API — dispatches based on policy engine ────────────────

    /// Protect a value using the named policy.
    /// Dispatches to encrypt, mask, or hash based on the policy's engine.
    /// This is the recommended API for most users.
    pub fn protect(&self, policy_name: &str, value: &str) -> Result<ProtectResult> {
        let policy = self.get_policy(policy_name)?;
        match policy.engine.as_str() {
            "ff1" | "ff3" | "aes" => self.encrypt(policy_name, value),
            "mask" => {
                let pattern = policy.alphabet.as_deref().unwrap_or("full");
                self.mask(value, pattern)
            }
            "hash" => self.hash(policy_name, value),
            engine => Err(CypheraError::UnknownEngine(engine.to_string())),
        }
    }

    /// Access (reverse) a protected value.
    /// Decrypts if reversible, errors if the policy uses an irreversible engine.
    pub fn access(&self, policy_name: &str, value: &str) -> Result<ProtectResult> {
        let policy = self.get_policy(policy_name)?;
        match policy.engine.as_str() {
            "ff1" | "ff3" | "aes" => self.decrypt(policy_name, value),
            "mask" | "hash" => Err(CypheraError::UnknownEngine(
                format!("cannot reverse '{}' — {} is irreversible", policy_name, policy.engine)
            )),
            engine => Err(CypheraError::UnknownEngine(engine.to_string())),
        }
    }

    /// Encrypt multiple values in batch.
    pub fn encrypt_batch(
        &self,
        items: &[(&str, &str)], // (policy_name, plaintext)
    ) -> Vec<Result<ProtectResult>> {
        items.iter().map(|(p, v)| self.encrypt(p, v)).collect()
    }

    /// Decrypt multiple values in batch.
    pub fn decrypt_batch(
        &self,
        items: &[(&str, &str)], // (policy_name, ciphertext)
    ) -> Vec<Result<ProtectResult>> {
        items.iter().map(|(p, v)| self.decrypt(p, v)).collect()
    }

    // ── Internal ────────────────────────────────────────────────────────

    fn get_policy(&self, name: &str) -> Result<PolicyEntry> {
        self.policies
            .get(name)
            .cloned()
            .ok_or_else(|| CypheraError::PolicyNotFound(name.to_string()))
    }

    fn resolve_alphabet(&self, policy: &PolicyEntry) -> Alphabet {
        match policy.alphabet.as_deref() {
            Some("digits") => cyphera_alphabet::digits(),
            Some("hex") => cyphera_alphabet::hex_lower(),
            Some("alphanumeric_lower") | Some("alphanumeric") => {
                cyphera_alphabet::alphanumeric_lower()
            }
            Some("alphanumeric_full") => cyphera_alphabet::alphanumeric(),
            // Default: alphanumeric lowercase (the secure, non-exploding default)
            _ => cyphera_alphabet::alphanumeric_lower(),
        }
    }

    fn resolve_key(&self, policy: &PolicyEntry) -> Result<KeyRecord> {
        let key_ref = policy
            .key_ref
            .as_deref()
            .or(self.default_key_ref.as_deref())
            .ok_or_else(|| CypheraError::PolicyNotFound("no key_ref in policy and no default set".to_string()))?;

        Ok(self.key_provider.resolve(key_ref)?)
    }

    fn log_event(&self, policy: &str, operation: &str, engine: &str, key: &KeyRecord, success: bool) {
        let event = AuditEvent {
            operation: operation.to_string(),
            policy: policy.to_string(),
            key_ref: Some(key.key_ref.clone()),
            key_version: Some(key.version),
            engine: engine.to_string(),
            success,
            error: None,
            context: HashMap::new(),
            timestamp: String::new(), // TODO: proper timestamp
        };
        self.logger.log(&event);
    }
}

/// Builder for full control over Client construction
pub struct ClientBuilder {
    policies: HashMap<String, PolicyEntry>,
    key_provider: Option<Box<dyn KeyProvider>>,
    logger: Option<Box<dyn AuditLogger>>,
    default_key_ref: Option<String>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            key_provider: None,
            logger: None,
            default_key_ref: None,
        }
    }

    pub fn policy_file(mut self, path: &str) -> std::result::Result<Self, CypheraError> {
        let contents = std::fs::read_to_string(path)?;
        let pf = PolicyFile::from_yaml(&contents)?;
        self.policies = pf.policies;
        Ok(self)
    }

    pub fn policy(mut self, pf: PolicyFile) -> Self {
        self.policies = pf.policies;
        self
    }

    pub fn key_provider(mut self, provider: Box<dyn KeyProvider>) -> Self {
        self.key_provider = Some(provider);
        self
    }

    pub fn logger(mut self, logger: Box<dyn AuditLogger>) -> Self {
        self.logger = Some(logger);
        self
    }

    pub fn default_key_ref(mut self, key_ref: &str) -> Self {
        self.default_key_ref = Some(key_ref.to_string());
        self
    }

    pub fn build(self) -> std::result::Result<Client, CypheraError> {
        let key_provider = self.key_provider
            .ok_or_else(|| CypheraError::PolicyNotFound("key_provider is required".to_string()))?;

        Ok(Client {
            policies: self.policies,
            key_provider: Arc::from(key_provider),
            logger: match self.logger {
                Some(l) => Arc::from(l) as Arc<dyn AuditLogger>,
                None => Arc::new(NoopLogger) as Arc<dyn AuditLogger>,
            },
            default_key_ref: self.default_key_ref,
        })
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        hex::decode("2B7E151628AED2A6ABF7158809CF4F3C").unwrap()
    }

    fn test_tweak() -> Vec<u8> {
        vec![0u8; 8]
    }

    // ── Quick start (with_defaults) ─────────────────────────────────────

    #[test]
    fn test_encrypt_decrypt_ssn() {
        let client = Client::with_defaults(&test_key(), &test_tweak());
        let ct = client.encrypt("ssn", "123-45-6789").unwrap();
        assert_ne!(ct.output, "123-45-6789");
        // Dashes preserved
        assert_eq!(ct.output.matches('-').count(), 2);
        // Roundtrip
        let pt = client.decrypt("ssn", &ct.output).unwrap();
        assert_eq!(pt.output, "123-45-6789");
    }

    #[test]
    fn test_encrypt_decrypt_card() {
        let client = Client::with_defaults(&test_key(), &test_tweak());
        let ct = client.encrypt("card", "4111-1111-1111-1111").unwrap();
        // Dashes preserved
        assert_eq!(ct.output.matches('-').count(), 3);
        let pt = client.decrypt("card", &ct.output).unwrap();
        assert_eq!(pt.output, "4111-1111-1111-1111");
    }

    #[test]
    fn test_encrypt_decrypt_phone() {
        let client = Client::with_defaults(&test_key(), &test_tweak());
        let ct = client.encrypt("phone", "(555) 867-5309").unwrap();
        // Structural chars preserved
        assert!(ct.output.contains('('));
        assert!(ct.output.contains(')'));
        assert!(ct.output.contains(' '));
        assert!(ct.output.contains('-'));
        let pt = client.decrypt("phone", &ct.output).unwrap();
        assert_eq!(pt.output, "(555) 867-5309");
    }

    #[test]
    fn test_encrypt_decrypt_dob() {
        let client = Client::with_defaults(&test_key(), &test_tweak());
        let ct = client.encrypt("dob", "03/15/1990").unwrap();
        assert_eq!(ct.output.matches('/').count(), 2);
        let pt = client.decrypt("dob", &ct.output).unwrap();
        assert_eq!(pt.output, "03/15/1990");
    }

    #[test]
    fn test_encrypt_plain_string() {
        let client = Client::with_defaults(&test_key(), &test_tweak());
        let ct = client.encrypt("name", "johnsmith").unwrap();
        let pt = client.decrypt("name", &ct.output).unwrap();
        assert_eq!(pt.output, "johnsmith");
    }

    #[test]
    fn test_deterministic() {
        let client = Client::with_defaults(&test_key(), &test_tweak());
        let a = client.encrypt("ssn", "123-45-6789").unwrap();
        let b = client.encrypt("ssn", "123-45-6789").unwrap();
        assert_eq!(a.output, b.output);
    }

    #[test]
    fn test_different_inputs_different_outputs() {
        let client = Client::with_defaults(&test_key(), &test_tweak());
        let a = client.encrypt("ssn", "123-45-6789").unwrap();
        let b = client.encrypt("ssn", "987-65-4321").unwrap();
        assert_ne!(a.output, b.output);
    }

    // ── Masking ─────────────────────────────────────────────────────────

    #[test]
    fn test_mask_last4() {
        let client = Client::with_defaults(&test_key(), &test_tweak());
        let r = client.mask("123-45-6789", "last4").unwrap();
        assert_eq!(r.output, "*******6789");
        assert!(!r.reversible);
    }

    #[test]
    fn test_mask_full() {
        let client = Client::with_defaults(&test_key(), &test_tweak());
        let r = client.mask("123-45-6789", "full").unwrap();
        assert_eq!(r.output, "***-**-****");
        assert!(!r.reversible);
    }

    // ── Hashing ─────────────────────────────────────────────────────────

    #[test]
    fn test_hash_deterministic() {
        let client = Client::with_defaults(&test_key(), &test_tweak());
        let a = client.hash("ssn", "123-45-6789").unwrap();
        let b = client.hash("ssn", "123-45-6789").unwrap();
        assert_eq!(a.output, b.output);
        assert!(!a.reversible);
    }

    #[test]
    fn test_hash_different_inputs() {
        let client = Client::with_defaults(&test_key(), &test_tweak());
        let a = client.hash("ssn", "123-45-6789").unwrap();
        let b = client.hash("ssn", "987-65-4321").unwrap();
        assert_ne!(a.output, b.output);
    }

    // ── Batch ───────────────────────────────────────────────────────────

    #[test]
    fn test_batch_encrypt() {
        let client = Client::with_defaults(&test_key(), &test_tweak());
        let items = vec![
            ("ssn", "123-45-6789"),
            ("card", "4111-1111-1111-1111"),
            ("dob", "03/15/1990"),
        ];
        let results = client.encrypt_batch(&items);
        assert_eq!(results.len(), 3);
        for r in &results {
            assert!(r.is_ok());
        }
    }

    // ── Policy-driven ───────────────────────────────────────────────────

    #[test]
    fn test_policy_from_yaml() {
        let yaml = r#"
policies:
  ssn:
    engine: ff1
    alphabet: alphanumeric
    key_ref: mykey
  card:
    engine: ff3
    alphabet: digits
    key_ref: mykey
"#;
        let pf = PolicyFile::from_yaml(yaml).unwrap();
        let provider = MemoryProvider::new(vec![
            KeyRecord {
                key_ref: "mykey".into(),
                version: 1,
                status: KeyStatus::Active,
                material: test_key(),
                tweak: test_tweak(),
            },
        ]);

        let client = Client::from_policy(pf, Box::new(provider));

        // SSN uses ff1 + alphanumeric
        let ct = client.encrypt("ssn", "123-45-6789").unwrap();
        assert_eq!(ct.engine, "ff1");
        let pt = client.decrypt("ssn", &ct.output).unwrap();
        assert_eq!(pt.output, "123-45-6789");

        // Card uses ff3 + digits — no structural extraction needed since all digits
        let ct2 = client.encrypt("card", "4111111111111111").unwrap();
        assert_eq!(ct2.engine, "ff3");
        let pt2 = client.decrypt("card", &ct2.output).unwrap();
        assert_eq!(pt2.output, "4111111111111111");
    }

    // ── Protect / Access (generic API) ─────────────────────────────────

    #[test]
    fn test_protect_dispatches_to_encrypt() {
        let client = Client::with_defaults(&test_key(), &test_tweak());
        let r = client.protect("ssn", "123-45-6789").unwrap();
        assert!(r.reversible);
        assert_eq!(r.engine, "ff1");
        // access reverses it
        let pt = client.access("ssn", &r.output).unwrap();
        assert_eq!(pt.output, "123-45-6789");
    }

    #[test]
    fn test_protect_with_mask_policy() {
        let yaml = r#"
policies:
  ssn_display:
    engine: mask
    alphabet: last4
    key_ref: k1
"#;
        let pf = PolicyFile::from_yaml(yaml).unwrap();
        let provider = MemoryProvider::new(vec![
            KeyRecord {
                key_ref: "k1".into(),
                version: 1,
                status: KeyStatus::Active,
                material: test_key(),
                tweak: test_tweak(),
            },
        ]);
        let client = Client::from_policy(pf, Box::new(provider));
        let r = client.protect("ssn_display", "123-45-6789").unwrap();
        assert_eq!(r.output, "*******6789");
        assert!(!r.reversible);
    }

    #[test]
    fn test_protect_with_hash_policy() {
        let yaml = r#"
policies:
  ssn_token:
    engine: hash
    key_ref: k1
"#;
        let pf = PolicyFile::from_yaml(yaml).unwrap();
        let provider = MemoryProvider::new(vec![
            KeyRecord {
                key_ref: "k1".into(),
                version: 1,
                status: KeyStatus::Active,
                material: test_key(),
                tweak: test_tweak(),
            },
        ]);
        let client = Client::from_policy(pf, Box::new(provider));
        let r = client.protect("ssn_token", "123-45-6789").unwrap();
        assert!(!r.reversible);
        assert!(!r.output.is_empty());
        // access should fail — hash is irreversible
        let err = client.access("ssn_token", &r.output);
        assert!(err.is_err());
    }

    // ── Error cases ─────────────────────────────────────────────────────

    #[test]
    fn test_unknown_policy() {
        let client = Client::with_defaults(&test_key(), &test_tweak());
        let r = client.encrypt("nonexistent", "hello");
        assert!(r.is_err());
    }

    // ── Builder ─────────────────────────────────────────────────────────

    #[test]
    fn test_builder() {
        let provider = MemoryProvider::new(vec![
            KeyRecord {
                key_ref: "k1".into(),
                version: 1,
                status: KeyStatus::Active,
                material: test_key(),
                tweak: test_tweak(),
            },
        ]);

        let yaml = r#"
policies:
  ssn:
    engine: ff1
    key_ref: k1
"#;
        let pf = PolicyFile::from_yaml(yaml).unwrap();

        let client = Client::builder()
            .policy(pf)
            .key_provider(Box::new(provider))
            .build()
            .unwrap();

        let ct = client.encrypt("ssn", "123456789").unwrap();
        let pt = client.decrypt("ssn", &ct.output).unwrap();
        assert_eq!(pt.output, "123456789");
    }
}
