use crate::alphabet::Alphabet;
use crate::audit::{AuditEvent, AuditLogger, NoopLogger};
use crate::keys::{KeyProvider, KeyRecord};
use crate::policy::{PolicyFile, PolicyEntry};
use thiserror::Error;
use std::collections::HashMap;
use std::sync::Arc;

use crate::format;

#[derive(Error, Debug)]
pub enum CypheraError {
    #[error("policy not found: {0}")]
    PolicyNotFound(String),
    #[error("key error: {0}")]
    Key(#[from] crate::keys::KeyError),
    #[error("policy error: {0}")]
    Policy(#[from] crate::policy::PolicyError),
    #[error("ff1 error: {0}")]
    FF1(#[from] crate::ff1::FF1Error),
    #[error("ff3 error: {0}")]
    FF3(#[from] crate::ff3::FF3Error),
    #[error("unknown engine: {0}")]
    UnknownEngine(String),
    #[error("input too short for masking")]
    MaskInputTooShort,
    #[error("hash error: {0}")]
    Hash(#[from] crate::hash::HashError),
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
    tag_index: HashMap<String, String>, // tag → policy name
    key_provider: Arc<dyn KeyProvider>,
    logger: Arc<dyn AuditLogger>,
    default_key_ref: Option<String>,
}

impl Client {
    /// Validate policies and build tag index. Errors on:
    /// - tag_enabled=true with no tag specified
    /// - duplicate tags across policies
    fn validate_and_build_tag_index(policies: &HashMap<String, PolicyEntry>) -> Result<HashMap<String, String>> {
        let mut index = HashMap::new();
        for (name, policy) in policies.iter() {
            if policy.tag_enabled {
                match &policy.tag {
                    None => return Err(CypheraError::PolicyNotFound(
                        format!("policy '{}' has tag_enabled=true but no tag specified", name)
                    )),
                    Some(tag) if tag.is_empty() => return Err(CypheraError::PolicyNotFound(
                        format!("policy '{}' has tag_enabled=true but tag is empty", name)
                    )),
                    Some(tag) => {
                        if let Some(existing) = index.get(tag) {
                            return Err(CypheraError::PolicyNotFound(
                                format!("tag collision: '{}' used by both '{}' and '{}'", tag, existing, name)
                            ));
                        }
                        index.insert(tag.clone(), name.clone());
                    }
                }
            }
        }
        Ok(index)
    }

    /// Create a client from a JSON policy file on disk.
    pub fn from_file(
        path: &str,
        key_provider: Box<dyn KeyProvider>,
    ) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let pf = PolicyFile::from_json(&contents)?;
        let policies = pf.policies;
        let tag_index = Self::validate_and_build_tag_index(&policies)?;
        Ok(Self {
            policies,
            tag_index,
            key_provider: Arc::from(key_provider),
            logger: Arc::new(NoopLogger),
            default_key_ref: None,
        })
    }

    /// Create a client from a PolicyFile struct
    pub fn from_policy(
        policy: PolicyFile,
        key_provider: Box<dyn KeyProvider>,
    ) -> Result<Self> {
        let policies = policy.policies;
        let tag_index = Self::validate_and_build_tag_index(&policies)?;
        Ok(Self {
            policies,
            tag_index,
            key_provider: Arc::from(key_provider),
            logger: Arc::new(NoopLogger),
            default_key_ref: None,
        })
    }

    /// Use the builder for full control
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    // ── Public API ──────────────────────────────────────────────────────

    /// Encrypt a value using the named policy.
    /// Structural characters (dashes, slashes, etc.) are preserved.
    /// Tag is prepended to the final output if tag_enabled.
    pub fn encrypt(&self, policy_name: &str, plaintext: &str) -> Result<ProtectResult> {
        let policy = self.get_policy(policy_name)?;
        let alphabet = self.resolve_alphabet(&policy);
        let key = self.resolve_key(&policy)?;

        // 1. Strip passthroughs
        let (extracted, template) = format::extract(plaintext, &alphabet);

        // 2. Validate
        if extracted.is_empty() {
            return Err(CypheraError::PolicyNotFound(
                "no encryptable characters in input".to_string()
            ));
        }

        // 3. Encrypt
        let encrypted = match policy.engine.as_str() {
            "ff1" => {
                let cipher = crate::ff1::FF1::new(&key.material, &key.tweak, alphabet)?;
                cipher.encrypt(&extracted)?
            }
            "ff3" => {
                let cipher = crate::ff3::FF3::new(&key.material, &key.tweak, alphabet)?;
                cipher.encrypt(&extracted)?
            }
            engine => return Err(CypheraError::UnknownEngine(engine.to_string())),
        };

        // 3. Reinsert passthroughs
        let with_passthroughs = format::reconstruct(&encrypted, &template);

        // 4. Prepend tag
        let output = if policy.tag_enabled {
            let tag = policy.tag.as_deref().unwrap_or("");
            format!("{}{}", tag, with_passthroughs)
        } else {
            with_passthroughs
        };

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

    /// Decrypt a value using the named policy. Strips tag if present.
    pub fn decrypt(&self, policy_name: &str, ciphertext: &str) -> Result<ProtectResult> {
        let policy = self.get_policy(policy_name)?;
        let alphabet = self.resolve_alphabet(&policy);
        let key = self.resolve_key(&policy)?;

        // 1. Strip tag
        let without_tag = if policy.tag_enabled {
            let tag_len = policy.tag.as_ref().map(|t| t.len()).unwrap_or(0);
            &ciphertext[tag_len..]
        } else {
            ciphertext
        };

        // 2. Strip passthroughs
        let (extracted, template) = format::extract(without_tag, &alphabet);

        // 3. Decrypt
        let decrypted = match policy.engine.as_str() {
            "ff1" => {
                let cipher = crate::ff1::FF1::new(&key.material, &key.tweak, alphabet)?;
                cipher.decrypt(&extracted)?
            }
            "ff3" => {
                let cipher = crate::ff3::FF3::new(&key.material, &key.tweak, alphabet)?;
                cipher.decrypt(&extracted)?
            }
            engine => return Err(CypheraError::UnknownEngine(engine.to_string())),
        };

        // 4. Reinsert passthroughs
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

    /// Mask a value — irreversible. Simple show/hide based on pattern.
    pub fn mask(&self, plaintext: &str, pattern: &str) -> Result<ProtectResult> {
        let output = match pattern {
            "last4" | "last_4" => crate::mask::last_n(plaintext, 4, '*'),
            "last2" | "last_2" => crate::mask::last_n(plaintext, 2, '*'),
            "first1" | "first_1" => crate::mask::first_n(plaintext, 1, '*'),
            "first3" | "first_3" => crate::mask::first_n(plaintext, 3, '*'),
            "full" => crate::mask::full(plaintext, '*'),
            _ => crate::mask::full(plaintext, '*'),
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
        let algorithm = policy.algorithm.as_deref().unwrap_or("sha256");

        let (output, key_ref, key_version) = if policy.key_ref.is_some() {
            let key = self.resolve_key(&policy)?;
            let out = crate::hash::hash(algorithm, Some(&key.material), plaintext)?;
            (out, Some(key.key_ref.clone()), Some(key.version))
        } else {
            let out = crate::hash::hash(algorithm, None, plaintext)?;
            (out, None, None)
        };

        Ok(ProtectResult {
            output,
            policy_name: policy_name.to_string(),
            engine: "hash".to_string(),
            key_ref,
            key_version,
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
            "ff1" | "ff3" | "aes_gcm" => self.encrypt(policy_name, value),
            "mask" => {
                let pattern = policy.pattern.as_deref().ok_or_else(||
                    CypheraError::PolicyNotFound("mask policy requires 'pattern' field".to_string())
                )?;
                self.mask(value, pattern)
            }
            "hash" => self.hash(policy_name, value),
            engine => Err(CypheraError::UnknownEngine(engine.to_string())),
        }
    }

    /// Access (reverse) a protected value using explicit policy name.
    pub fn access(&self, policy_name: &str, value: &str) -> Result<ProtectResult> {
        let policy = self.get_policy(policy_name)?;
        match policy.engine.as_str() {
            "ff1" | "ff3" | "aes_gcm" => self.decrypt(policy_name, value),
            "mask" | "hash" => Err(CypheraError::UnknownEngine(
                format!("cannot reverse '{}' — {} is irreversible", policy_name, policy.engine)
            )),
            engine => Err(CypheraError::UnknownEngine(engine.to_string())),
        }
    }

    /// Access (reverse) a protected value using the embedded tag.
    /// Looks up the tag from the first N chars, finds the policy, decrypts.
    /// Tags are checked longest-first to prevent prefix collisions.
    pub fn access_by_tag(&self, value: &str) -> Result<ProtectResult> {
        let mut tags: Vec<_> = self.tag_index.iter().collect();
        tags.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        for (tag, policy_name) in tags {
            if value.starts_with(tag.as_str()) {
                return self.access(policy_name, value);
            }
        }
        Err(CypheraError::PolicyNotFound(
            "no matching tag found — use access(policy_name, value) for untagged values".to_string()
        ))
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
            Some("digits") => crate::alphabet::digits(),
            Some("hex") => crate::alphabet::hex_lower(),
            Some("alpha_lower") => Alphabet::new("abcdefghijklmnopqrstuvwxyz").unwrap(),
            Some("alpha_upper") => Alphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap(),
            Some("alpha") => Alphabet::new("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap(),
            Some("alphanumeric") => crate::alphabet::alphanumeric(),
            Some(custom) => Alphabet::new(custom).unwrap_or_else(|_| crate::alphabet::alphanumeric()),
            // Default: alphanumeric radix 62
            None => crate::alphabet::alphanumeric(),
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
        let pf = PolicyFile::from_json(&contents)?;
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

        let policies = self.policies;
        let tag_index = Client::validate_and_build_tag_index(&policies)?;

        Ok(Client {
            policies,
            tag_index,
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

    fn test_client() -> Client {
        let json = r#"{"policies":{"ssn":{"engine":"ff1","alphabet":"alphanumeric","key_ref":"k1","tag":"s01"},"card":{"engine":"ff1","alphabet":"alphanumeric","key_ref":"k1","tag":"c01"},"phone":{"engine":"ff1","alphabet":"alphanumeric","key_ref":"k1","tag":"h01"},"dob":{"engine":"ff1","alphabet":"alphanumeric","key_ref":"k1","tag":"d01"},"name":{"engine":"ff1","alphabet":"alphanumeric","key_ref":"k1","tag":"n01"},"general":{"engine":"ff1","alphabet":"alphanumeric","key_ref":"k1","tag":"g01"}}}"#;
        let pf = PolicyFile::from_json(json).unwrap();
        let provider = crate::keys::MemoryProvider::new(vec![
            KeyRecord {
                key_ref: "k1".into(),
                version: 1,
                status: crate::keys::KeyStatus::Active,
                material: test_key(),
                tweak: test_tweak(),
            },
        ]);
        Client::from_policy(pf, Box::new(provider)).unwrap()
    }

    // ── Core tests ─────────────────────────────────────────────────

    #[test]
    fn test_encrypt_decrypt_ssn() {
        let client = test_client();
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
        let client = test_client();
        let ct = client.encrypt("card", "4111-1111-1111-1111").unwrap();
        // Dashes preserved
        assert_eq!(ct.output.matches('-').count(), 3);
        let pt = client.decrypt("card", &ct.output).unwrap();
        assert_eq!(pt.output, "4111-1111-1111-1111");
    }

    #[test]
    fn test_encrypt_decrypt_phone() {
        let client = test_client();
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
        let client = test_client();
        let ct = client.encrypt("dob", "03/15/1990").unwrap();
        assert_eq!(ct.output.matches('/').count(), 2);
        let pt = client.decrypt("dob", &ct.output).unwrap();
        assert_eq!(pt.output, "03/15/1990");
    }

    #[test]
    fn test_encrypt_plain_string() {
        let client = test_client();
        let ct = client.encrypt("name", "johnsmith").unwrap();
        let pt = client.decrypt("name", &ct.output).unwrap();
        assert_eq!(pt.output, "johnsmith");
    }

    #[test]
    fn test_deterministic() {
        let client = test_client();
        let a = client.encrypt("ssn", "123-45-6789").unwrap();
        let b = client.encrypt("ssn", "123-45-6789").unwrap();
        assert_eq!(a.output, b.output);
    }

    #[test]
    fn test_different_inputs_different_outputs() {
        let client = test_client();
        let a = client.encrypt("ssn", "123-45-6789").unwrap();
        let b = client.encrypt("ssn", "987-65-4321").unwrap();
        assert_ne!(a.output, b.output);
    }

    // ── Masking ─────────────────────────────────────────────────────────

    #[test]
    fn test_mask_last4() {
        let client = test_client();
        let r = client.mask("123-45-6789", "last4").unwrap();
        assert_eq!(r.output, "*******6789");
        assert!(!r.reversible);
    }

    #[test]
    fn test_mask_full() {
        let client = test_client();
        let r = client.mask("123-45-6789", "full").unwrap();
        assert_eq!(r.output, "***********");
        assert!(!r.reversible);
    }

    // ── Hashing ─────────────────────────────────────────────────────────

    #[test]
    fn test_hash_deterministic() {
        let client = test_client();
        let a = client.hash("ssn", "123-45-6789").unwrap();
        let b = client.hash("ssn", "123-45-6789").unwrap();
        assert_eq!(a.output, b.output);
        assert!(!a.reversible);
    }

    #[test]
    fn test_hash_different_inputs() {
        let client = test_client();
        let a = client.hash("ssn", "123-45-6789").unwrap();
        let b = client.hash("ssn", "987-65-4321").unwrap();
        assert_ne!(a.output, b.output);
    }

    // ── Batch ───────────────────────────────────────────────────────────

    #[test]
    fn test_batch_encrypt() {
        let client = test_client();
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
    fn test_policy_from_json() {
        let json = r#"{"policies":{"ssn":{"engine":"ff1","alphabet":"alphanumeric","key_ref":"mykey","tag_enabled":false},"card":{"engine":"ff3","alphabet":"digits","key_ref":"mykey","tag_enabled":false}}}"#;
        let pf = PolicyFile::from_json(json).unwrap();
        let provider = crate::keys::MemoryProvider::new(vec![
            KeyRecord {
                key_ref: "mykey".into(),
                version: 1,
                status: crate::keys::KeyStatus::Active,
                material: test_key(),
                tweak: test_tweak(),
            },
        ]);

        let client = Client::from_policy(pf, Box::new(provider)).unwrap();

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
        let client = test_client();
        let r = client.protect("ssn", "123-45-6789").unwrap();
        assert!(r.reversible);
        assert_eq!(r.engine, "ff1");
        // access reverses it
        let pt = client.access("ssn", &r.output).unwrap();
        assert_eq!(pt.output, "123-45-6789");
    }

    #[test]
    fn test_protect_with_mask_policy() {
        let json = r#"{"policies":{"ssn_display":{"engine":"mask","pattern":"last4","tag_enabled":false,"key_ref":"k1"}}}"#;
        let pf = PolicyFile::from_json(json).unwrap();
        let provider = crate::keys::MemoryProvider::new(vec![
            KeyRecord {
                key_ref: "k1".into(),
                version: 1,
                status: crate::keys::KeyStatus::Active,
                material: test_key(),
                tweak: test_tweak(),
            },
        ]);
        let client = Client::from_policy(pf, Box::new(provider)).unwrap();
        let r = client.protect("ssn_display", "123-45-6789").unwrap();
        assert_eq!(r.output, "*******6789");
        assert!(!r.reversible);
    }

    #[test]
    fn test_protect_with_hash_policy() {
        let json = r#"{"policies":{"ssn_token":{"engine":"hash","key_ref":"k1","tag_enabled":false}}}"#;
        let pf = PolicyFile::from_json(json).unwrap();
        let provider = crate::keys::MemoryProvider::new(vec![
            KeyRecord {
                key_ref: "k1".into(),
                version: 1,
                status: crate::keys::KeyStatus::Active,
                material: test_key(),
                tweak: test_tweak(),
            },
        ]);
        let client = Client::from_policy(pf, Box::new(provider)).unwrap();
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
        let client = test_client();
        let r = client.encrypt("nonexistent", "hello");
        assert!(r.is_err());
    }

    // ── Builder ─────────────────────────────────────────────────────────

    #[test]
    fn test_builder() {
        let provider = crate::keys::MemoryProvider::new(vec![
            KeyRecord {
                key_ref: "k1".into(),
                version: 1,
                status: crate::keys::KeyStatus::Active,
                material: test_key(),
                tweak: test_tweak(),
            },
        ]);

        let json = r#"{"policies":{"ssn":{"engine":"ff1","key_ref":"k1","tag_enabled":false}}}"#;
        let pf = PolicyFile::from_json(json).unwrap();

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
