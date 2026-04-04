use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("key not found: {0}")]
    NotFound(String),
    #[error("key version {version} not found for ref '{key_ref}'")]
    VersionNotFound { key_ref: String, version: u32 },
    #[error("key '{0}' is disabled")]
    Disabled(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyStatus {
    Active,
    Deprecated,
    Disabled,
}

#[derive(Debug, Clone)]
pub struct KeyRecord {
    pub key_ref: String,
    pub version: u32,
    pub status: KeyStatus,
    pub material: Vec<u8>,
    pub tweak: Vec<u8>,
}

/// Trait for key providers — implement this for memory, file, KMS, etc.
pub trait KeyProvider: Send + Sync {
    fn resolve(&self, key_ref: &str) -> Result<KeyRecord, KeyError>;
    fn resolve_version(&self, key_ref: &str, version: u32) -> Result<KeyRecord, KeyError>;
}

/// In-memory key provider for dev/testing
pub struct MemoryProvider {
    records: Vec<KeyRecord>,
}

impl MemoryProvider {
    pub fn new(records: Vec<KeyRecord>) -> Self {
        Self { records }
    }
}

impl KeyProvider for MemoryProvider {
    fn resolve(&self, key_ref: &str) -> Result<KeyRecord, KeyError> {
        self.records
            .iter()
            .filter(|r| r.key_ref == key_ref && r.status == KeyStatus::Active)
            .max_by_key(|r| r.version)
            .cloned()
            .ok_or_else(|| KeyError::NotFound(key_ref.to_string()))
    }

    fn resolve_version(&self, key_ref: &str, version: u32) -> Result<KeyRecord, KeyError> {
        self.records
            .iter()
            .find(|r| r.key_ref == key_ref && r.version == version)
            .cloned()
            .ok_or(KeyError::VersionNotFound {
                key_ref: key_ref.to_string(),
                version,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_provider() -> MemoryProvider {
        MemoryProvider::new(vec![
            KeyRecord {
                key_ref: "primary".into(),
                version: 1,
                status: KeyStatus::Deprecated,
                material: vec![0u8; 32],
                tweak: vec![0u8; 8],
            },
            KeyRecord {
                key_ref: "primary".into(),
                version: 2,
                status: KeyStatus::Active,
                material: vec![1u8; 32],
                tweak: vec![1u8; 8],
            },
        ])
    }

    #[test]
    fn test_resolve_gets_latest_active() {
        let p = test_provider();
        let k = p.resolve("primary").unwrap();
        assert_eq!(k.version, 2);
    }

    #[test]
    fn test_resolve_version() {
        let p = test_provider();
        let k = p.resolve_version("primary", 1).unwrap();
        assert_eq!(k.version, 1);
    }

    #[test]
    fn test_not_found() {
        let p = test_provider();
        assert!(p.resolve("nonexistent").is_err());
    }
}
