use crate::alphabet::Alphabet;
use crate::audit::{AuditEvent, AuditLogger, NoopLogger};
use crate::keys::{KeyProvider, KeyRecord};
use crate::configuration::{ConfigurationFile, Configuration};
use thiserror::Error;
use std::collections::HashMap;
use std::sync::Arc;

use crate::format;

#[derive(Error, Debug)]
pub enum CypheraError {
    #[error("configuration not found: {0}")]
    ConfigurationNotFound(String),
    #[error("key error: {0}")]
    Key(#[from] crate::keys::KeyError),
    #[error("configuration error: {0}")]
    Policy(#[from] crate::configuration::ConfigurationError),
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
    #[error("configuration '{0}' has header_enabled=true; use access(value) — the header identifies the configuration. The two-arg form is for header_enabled=false configurations only.")]
    ExplicitAccessOnHeaderedConfiguration(String),
}

/// Result type alias for Cyphera operations
pub type Result<T> = std::result::Result<T, CypheraError>;

/// The output of an encrypt/decrypt/mask/hash operation
#[derive(Debug, Clone)]
pub struct ProtectResult {
    pub output: String,
    pub configuration_name: String,
    pub engine: String,
    pub key_ref: Option<String>,
    pub key_version: Option<u32>,
    pub reversible: bool,
}

/// The main Cyphera client. This is what developers use.
pub struct Client {
    configurations: HashMap<String, Configuration>,
    header_index: HashMap<String, String>, // header → configuration name
    key_provider: Arc<dyn KeyProvider>,
    logger: Arc<dyn AuditLogger>,
    default_key_ref: Option<String>,
}

impl Client {
    /// Validate configurations and build header index. Errors on:
    /// - header_enabled=true with no header specified
    /// - duplicate headers across configurations
    fn validate_and_build_header_index(configurations: &HashMap<String, Configuration>) -> Result<HashMap<String, String>> {
        let mut index = HashMap::new();
        for (name, configuration) in configurations.iter() {
            if configuration.header_enabled {
                match &configuration.header {
                    None => return Err(CypheraError::ConfigurationNotFound(
                        format!("configuration '{}' has header_enabled=true but no header specified", name)
                    )),
                    Some(header) if header.is_empty() => return Err(CypheraError::ConfigurationNotFound(
                        format!("configuration '{}' has header_enabled=true but header is empty", name)
                    )),
                    Some(header) => {
                        if let Some(existing) = index.get(header) {
                            return Err(CypheraError::ConfigurationNotFound(
                                format!("header collision: '{}' used by both '{}' and '{}'", header, existing, name)
                            ));
                        }
                        index.insert(header.clone(), name.clone());
                    }
                }
            }
        }
        Ok(index)
    }

    /// Auto-discover the configuration file. Checks, in order:
    ///   1. The `CYPHERA_CONFIG_FILE` environment variable
    ///   2. `./cyphera.json` in the current working directory
    ///   3. `/etc/cyphera/cyphera.json` system-wide path
    ///
    /// Errors with a stable message if none are found.
    pub fn load(key_provider: Box<dyn KeyProvider>) -> Result<Self> {
        let candidates: Vec<String> = std::env::var("CYPHERA_CONFIG_FILE")
            .ok()
            .into_iter()
            .chain(std::iter::once("./cyphera.json".to_string()))
            .chain(std::iter::once("/etc/cyphera/cyphera.json".to_string()))
            .collect();

        for path in &candidates {
            if std::path::Path::new(path).exists() {
                return Self::from_file(path, key_provider);
            }
        }
        Err(CypheraError::ConfigurationNotFound(
            "No configuration file found. Checked: CYPHERA_CONFIG_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json".to_string()
        ))
    }

    /// Create a client from a JSON configuration file on disk.
    pub fn from_file(
        path: &str,
        key_provider: Box<dyn KeyProvider>,
    ) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let pf = ConfigurationFile::from_json(&contents)?;
        let configurations = pf.configurations;
        let header_index = Self::validate_and_build_header_index(&configurations)?;
        Ok(Self {
            configurations,
            header_index,
            key_provider: Arc::from(key_provider),
            logger: Arc::new(NoopLogger),
            default_key_ref: None,
        })
    }

    /// Create a client from a ConfigurationFile struct
    pub fn from_configuration(
        configuration: ConfigurationFile,
        key_provider: Box<dyn KeyProvider>,
    ) -> Result<Self> {
        let configurations = configuration.configurations;
        let header_index = Self::validate_and_build_header_index(&configurations)?;
        Ok(Self {
            configurations,
            header_index,
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

    /// Encrypt a value using the named configuration.
    /// Structural characters (dashes, slashes, etc.) are preserved.
    /// Tag is prepended to the final output if header_enabled.
    pub fn encrypt(&self, configuration_name: &str, plaintext: &str) -> Result<ProtectResult> {
        let configuration = self.get_configuration(configuration_name)?;
        let alphabet = self.resolve_alphabet(&configuration);
        let key = self.resolve_key(&configuration)?;

        // 1. Strip passthroughs
        let (extracted, template) = format::extract(plaintext, &alphabet);

        // 2. Validate
        if extracted.is_empty() {
            return Err(CypheraError::ConfigurationNotFound(
                "no encryptable characters in input".to_string()
            ));
        }

        // 3. Encrypt
        let encrypted = match configuration.engine.as_str() {
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

        // 4. Prepend header
        let output = if configuration.header_enabled {
            let header = configuration.header.as_deref().unwrap_or("");
            format!("{}{}", header, with_passthroughs)
        } else {
            with_passthroughs
        };

        self.log_event(configuration_name, "encrypt", &configuration.engine, &key, true);

        Ok(ProtectResult {
            output,
            configuration_name: configuration_name.to_string(),
            engine: configuration.engine.clone(),
            key_ref: Some(key.key_ref.clone()),
            key_version: Some(key.version),
            reversible: true,
        })
    }

    /// Decrypt a value using the named configuration. The configuration must
    /// have `header_enabled = false` — the two-arg form treats the input as
    /// raw headerless ciphertext. For headered configurations, use
    /// `access_by_header(value)` so the header identifies the configuration.
    pub fn decrypt(&self, configuration_name: &str, ciphertext: &str) -> Result<ProtectResult> {
        let configuration = self.get_configuration(configuration_name)?;
        if configuration.header_enabled {
            return Err(CypheraError::ExplicitAccessOnHeaderedConfiguration(
                configuration_name.to_string(),
            ));
        }
        self.decrypt_raw(configuration_name, ciphertext)
    }

    /// Internal: decrypt assuming `ciphertext` is already header-stripped.
    /// Used by `decrypt` (after the header_enabled=false check) and by
    /// `access_by_header` (which strips the header itself).
    fn decrypt_raw(&self, configuration_name: &str, ciphertext: &str) -> Result<ProtectResult> {
        let configuration = self.get_configuration(configuration_name)?;
        let alphabet = self.resolve_alphabet(&configuration);
        let key = self.resolve_key(&configuration)?;

        // Strip passthroughs.
        let (extracted, template) = format::extract(ciphertext, &alphabet);

        // 3. Decrypt
        let decrypted = match configuration.engine.as_str() {
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

        self.log_event(configuration_name, "decrypt", &configuration.engine, &key, true);

        Ok(ProtectResult {
            output,
            configuration_name: configuration_name.to_string(),
            engine: configuration.engine.clone(),
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
            configuration_name: "mask".to_string(),
            engine: "mask".to_string(),
            key_ref: None,
            key_version: None,
            reversible: false,
        })
    }

    /// Hash a value — irreversible, deterministic.
    pub fn hash(&self, configuration_name: &str, plaintext: &str) -> Result<ProtectResult> {
        let configuration = self.get_configuration(configuration_name)?;
        let algorithm = configuration.algorithm.as_deref().unwrap_or("sha256");

        let (output, key_ref, key_version) = if configuration.key_ref.is_some() {
            let key = self.resolve_key(&configuration)?;
            let out = crate::hash::hash(algorithm, Some(&key.material), plaintext)?;
            (out, Some(key.key_ref.clone()), Some(key.version))
        } else {
            let out = crate::hash::hash(algorithm, None, plaintext)?;
            (out, None, None)
        };

        Ok(ProtectResult {
            output,
            configuration_name: configuration_name.to_string(),
            engine: "hash".to_string(),
            key_ref,
            key_version,
            reversible: false,
        })
    }

    // ── Generic API — dispatches based on configuration engine ────────────────

    /// Protect a value using the named configuration.
    /// Dispatches to encrypt, mask, or hash based on the configuration&apos;s engine.
    /// This is the recommended API for most users.
    pub fn protect(&self, configuration_name: &str, value: &str) -> Result<ProtectResult> {
        let configuration = self.get_configuration(configuration_name)?;
        match configuration.engine.as_str() {
            "ff1" | "ff3" | "aes_gcm" => self.encrypt(configuration_name, value),
            "mask" => {
                let pattern = configuration.pattern.as_deref().ok_or_else(||
                    CypheraError::ConfigurationNotFound("mask configuration requires 'pattern' field".to_string())
                )?;
                self.mask(value, pattern)
            }
            "hash" => self.hash(configuration_name, value),
            engine => Err(CypheraError::UnknownEngine(engine.to_string())),
        }
    }

    /// Access (reverse) a protected value using explicit configuration name.
    pub fn access(&self, configuration_name: &str, value: &str) -> Result<ProtectResult> {
        let configuration = self.get_configuration(configuration_name)?;
        match configuration.engine.as_str() {
            "ff1" | "ff3" | "aes_gcm" => self.decrypt(configuration_name, value),
            "mask" | "hash" => Err(CypheraError::UnknownEngine(
                format!("cannot reverse '{}' — {} is irreversible", configuration_name, configuration.engine)
            )),
            engine => Err(CypheraError::UnknownEngine(engine.to_string())),
        }
    }

    /// Access (reverse) a protected value using the embedded header (DPH).
    /// Looks up the header from the first N chars, finds the configuration,
    /// strips the header, and decrypts. Headers are checked longest-first to
    /// prevent prefix collisions.
    pub fn access_by_header(&self, value: &str) -> Result<ProtectResult> {
        let mut headers: Vec<_> = self.header_index.iter().collect();
        headers.sort_by_key(|a| std::cmp::Reverse(a.0.len()));
        for (header, configuration_name) in headers {
            if value.starts_with(header.as_str()) {
                let configuration = self.get_configuration(configuration_name)?;
                match configuration.engine.as_str() {
                    "ff1" | "ff3" | "aes_gcm" => {
                        let stripped = &value[header.len()..];
                        return self.decrypt_raw(configuration_name, stripped);
                    }
                    "mask" | "hash" => {
                        return Err(CypheraError::UnknownEngine(
                            format!("cannot reverse '{}' — {} is irreversible", configuration_name, configuration.engine)
                        ));
                    }
                    engine => return Err(CypheraError::UnknownEngine(engine.to_string())),
                }
            }
        }
        Err(CypheraError::ConfigurationNotFound(
            "no matching header found — use access(configuration_name, value) for headerless values".to_string()
        ))
    }

    /// Encrypt multiple values in batch.
    pub fn encrypt_batch(
        &self,
        items: &[(&str, &str)], // (configuration_name, plaintext)
    ) -> Vec<Result<ProtectResult>> {
        items.iter().map(|(p, v)| self.encrypt(p, v)).collect()
    }

    /// Decrypt multiple values in batch.
    pub fn decrypt_batch(
        &self,
        items: &[(&str, &str)], // (configuration_name, ciphertext)
    ) -> Vec<Result<ProtectResult>> {
        items.iter().map(|(p, v)| self.decrypt(p, v)).collect()
    }

    // ── Internal ────────────────────────────────────────────────────────

    fn get_configuration(&self, name: &str) -> Result<Configuration> {
        self.configurations
            .get(name)
            .cloned()
            .ok_or_else(|| CypheraError::ConfigurationNotFound(name.to_string()))
    }

    fn resolve_alphabet(&self, configuration: &Configuration) -> Alphabet {
        match configuration.alphabet.as_deref() {
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

    fn resolve_key(&self, configuration: &Configuration) -> Result<KeyRecord> {
        let key_ref = configuration
            .key_ref
            .as_deref()
            .or(self.default_key_ref.as_deref())
            .ok_or_else(|| CypheraError::ConfigurationNotFound("no key_ref in configuration and no default set".to_string()))?;

        Ok(self.key_provider.resolve(key_ref)?)
    }

    fn log_event(&self, configuration: &str, operation: &str, engine: &str, key: &KeyRecord, success: bool) {
        let event = AuditEvent {
            operation: operation.to_string(),
            configuration: configuration.to_string(),
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
    configurations: HashMap<String, Configuration>,
    key_provider: Option<Box<dyn KeyProvider>>,
    logger: Option<Box<dyn AuditLogger>>,
    default_key_ref: Option<String>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            configurations: HashMap::new(),
            key_provider: None,
            logger: None,
            default_key_ref: None,
        }
    }

    pub fn configuration_file(mut self, path: &str) -> std::result::Result<Self, CypheraError> {
        let contents = std::fs::read_to_string(path)?;
        let pf = ConfigurationFile::from_json(&contents)?;
        self.configurations = pf.configurations;
        Ok(self)
    }

    pub fn configuration(mut self, cf: ConfigurationFile) -> Self {
        self.configurations = cf.configurations;
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
            .ok_or_else(|| CypheraError::ConfigurationNotFound("key_provider is required".to_string()))?;

        let configurations = self.configurations;
        let header_index = Client::validate_and_build_header_index(&configurations)?;

        Ok(Client {
            configurations,
            header_index,
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
        let json = r#"{"configurations":{"ssn":{"engine":"ff1","alphabet":"alphanumeric","key_ref":"k1","header":"s01"},"card":{"engine":"ff1","alphabet":"alphanumeric","key_ref":"k1","header":"c01"},"phone":{"engine":"ff1","alphabet":"alphanumeric","key_ref":"k1","header":"h01"},"dob":{"engine":"ff1","alphabet":"alphanumeric","key_ref":"k1","header":"d01"},"name":{"engine":"ff1","alphabet":"alphanumeric","key_ref":"k1","header":"n01"},"general":{"engine":"ff1","alphabet":"alphanumeric","key_ref":"k1","header":"g01"}}}"#;
        let pf = ConfigurationFile::from_json(json).unwrap();
        let provider = crate::keys::MemoryProvider::new(vec![
            KeyRecord {
                key_ref: "k1".into(),
                version: 1,
                status: crate::keys::KeyStatus::Active,
                material: test_key(),
                tweak: test_tweak(),
            },
        ]);
        Client::from_configuration(pf, Box::new(provider)).unwrap()
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
        let pt = client.access_by_header(&ct.output).unwrap();
        assert_eq!(pt.output, "123-45-6789");
    }

    #[test]
    fn test_encrypt_decrypt_card() {
        let client = test_client();
        let ct = client.encrypt("card", "4111-1111-1111-1111").unwrap();
        // Dashes preserved
        assert_eq!(ct.output.matches('-').count(), 3);
        let pt = client.access_by_header(&ct.output).unwrap();
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
        let pt = client.access_by_header(&ct.output).unwrap();
        assert_eq!(pt.output, "(555) 867-5309");
    }

    #[test]
    fn test_encrypt_decrypt_dob() {
        let client = test_client();
        let ct = client.encrypt("dob", "03/15/1990").unwrap();
        assert_eq!(ct.output.matches('/').count(), 2);
        let pt = client.access_by_header(&ct.output).unwrap();
        assert_eq!(pt.output, "03/15/1990");
    }

    #[test]
    fn test_encrypt_plain_string() {
        let client = test_client();
        let ct = client.encrypt("name", "johnsmith").unwrap();
        let pt = client.access_by_header(&ct.output).unwrap();
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
        let json = r#"{"configurations":{"ssn":{"engine":"ff1","alphabet":"alphanumeric","key_ref":"mykey","header_enabled":false},"card":{"engine":"ff3","alphabet":"digits","key_ref":"mykey","header_enabled":false}}}"#;
        let pf = ConfigurationFile::from_json(json).unwrap();
        let provider = crate::keys::MemoryProvider::new(vec![
            KeyRecord {
                key_ref: "mykey".into(),
                version: 1,
                status: crate::keys::KeyStatus::Active,
                material: test_key(),
                tweak: test_tweak(),
            },
        ]);

        let client = Client::from_configuration(pf, Box::new(provider)).unwrap();

        // SSN uses ff1 + alphanumeric, header_enabled=false → use decrypt(name, ct)
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
        // access reverses it via the header (header_enabled=true on ssn)
        let pt = client.access_by_header(&r.output).unwrap();
        assert_eq!(pt.output, "123-45-6789");
    }

    #[test]
    fn test_protect_with_mask_policy() {
        let json = r#"{"configurations":{"ssn_display":{"engine":"mask","pattern":"last4","header_enabled":false,"key_ref":"k1"}}}"#;
        let pf = ConfigurationFile::from_json(json).unwrap();
        let provider = crate::keys::MemoryProvider::new(vec![
            KeyRecord {
                key_ref: "k1".into(),
                version: 1,
                status: crate::keys::KeyStatus::Active,
                material: test_key(),
                tweak: test_tweak(),
            },
        ]);
        let client = Client::from_configuration(pf, Box::new(provider)).unwrap();
        let r = client.protect("ssn_display", "123-45-6789").unwrap();
        assert_eq!(r.output, "*******6789");
        assert!(!r.reversible);
    }

    #[test]
    fn test_protect_with_hash_policy() {
        let json = r#"{"configurations":{"ssn_token":{"engine":"hash","key_ref":"k1","header_enabled":false}}}"#;
        let pf = ConfigurationFile::from_json(json).unwrap();
        let provider = crate::keys::MemoryProvider::new(vec![
            KeyRecord {
                key_ref: "k1".into(),
                version: 1,
                status: crate::keys::KeyStatus::Active,
                material: test_key(),
                tweak: test_tweak(),
            },
        ]);
        let client = Client::from_configuration(pf, Box::new(provider)).unwrap();
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

        let json = r#"{"configurations":{"ssn":{"engine":"ff1","key_ref":"k1","header_enabled":false}}}"#;
        let pf = ConfigurationFile::from_json(json).unwrap();

        let client = Client::builder()
            .configuration(pf)
            .key_provider(Box::new(provider))
            .build()
            .unwrap();

        // header_enabled=false → use decrypt(name, ct)
        let ct = client.encrypt("ssn", "123456789").unwrap();
        let pt = client.decrypt("ssn", &ct.output).unwrap();
        assert_eq!(pt.output, "123456789");
    }

    // ── New error condition: 2-arg access on headered config ──────────────

    #[test]
    fn test_decrypt_on_headered_config_errors() {
        let client = test_client();
        let ct = client.encrypt("ssn", "123-45-6789").unwrap();
        // ssn has header_enabled=true; calling decrypt(name, ct) must error.
        let err = client.decrypt("ssn", &ct.output);
        assert!(matches!(
            err,
            Err(CypheraError::ExplicitAccessOnHeaderedConfiguration(ref n)) if n == "ssn"
        ));
    }

    #[test]
    fn test_access_on_headered_config_errors() {
        let client = test_client();
        let ct = client.protect("ssn", "123-45-6789").unwrap();
        // Same error from access() — it routes to decrypt() for ff1/ff3 engines.
        let err = client.access("ssn", &ct.output);
        assert!(matches!(
            err,
            Err(CypheraError::ExplicitAccessOnHeaderedConfiguration(ref n)) if n == "ssn"
        ));
    }

    // ── load() auto-discovery ─────────────────────────────────────────────

    #[test]
    fn test_load_errors_when_no_config_file() {
        // Make sure CYPHERA_CONFIG_FILE is unset and we're in a temp dir
        // with no cyphera.json. /etc/cyphera/cyphera.json is unlikely to
        // exist in CI, but we test the error path defensively.
        let tmp = std::env::temp_dir().join("cyphera-rust-load-test-empty");
        std::fs::create_dir_all(&tmp).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&tmp).unwrap();
        std::env::remove_var("CYPHERA_CONFIG_FILE");

        let provider = crate::keys::MemoryProvider::new(vec![]);
        let r = Client::load(Box::new(provider));

        std::env::set_current_dir(prev).unwrap();
        std::fs::remove_dir_all(&tmp).ok();

        // Either an error from no file found, or /etc/cyphera/cyphera.json
        // exists on this machine and the load succeeded — either is OK
        // (we only care that the method exists and is invokable).
        if let Err(CypheraError::ConfigurationNotFound(msg)) = &r {
            assert!(msg.contains("CYPHERA_CONFIG_FILE"));
            assert!(msg.contains("./cyphera.json"));
            assert!(msg.contains("/etc/cyphera/cyphera.json"));
        }
    }

    #[test]
    fn test_load_uses_env_var() {
        let tmp = std::env::temp_dir().join("cyphera-rust-load-test-env");
        std::fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("custom-cyphera.json");
        std::fs::write(&path,
            r#"{"configurations":{"ssn":{"engine":"ff1","alphabet":"alphanumeric","key_ref":"k","header_enabled":false}}}"#).unwrap();
        std::env::set_var("CYPHERA_CONFIG_FILE", &path);
        let provider = crate::keys::MemoryProvider::new(vec![
            KeyRecord {
                key_ref: "k".into(),
                version: 1,
                status: crate::keys::KeyStatus::Active,
                material: test_key(),
                tweak: test_tweak(),
            },
        ]);
        let client = Client::load(Box::new(provider)).unwrap();
        std::env::remove_var("CYPHERA_CONFIG_FILE");
        std::fs::remove_dir_all(&tmp).ok();

        // Confirm the configuration loaded
        let ct = client.encrypt("ssn", "123456789").unwrap();
        let pt = client.decrypt("ssn", &ct.output).unwrap();
        assert_eq!(pt.output, "123456789");
    }
}
