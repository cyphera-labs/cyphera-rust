use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigurationError {
    #[error("configuration not found: {0}")]
    NotFound(String),
    #[error("failed to parse configuration file: {0}")]
    ParseError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configuration {
    pub engine: String,
    pub alphabet: Option<String>,
    pub key_ref: Option<String>,
    pub header: Option<String>,
    #[serde(default = "default_header_enabled")]
    pub header_enabled: bool,
    #[serde(default = "default_header_length")]
    pub header_length: usize,
    pub mode: Option<String>,
    pub pattern: Option<String>,     // for mask engine
    pub algorithm: Option<String>,   // for hash engine
}

fn default_header_enabled() -> bool { true }
fn default_header_length() -> usize { 3 }

impl Configuration {
    pub fn is_reversible(&self) -> bool {
        matches!(self.engine.as_str(), "ff1" | "ff3" | "aes_gcm")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurationFile {
    pub configurations: std::collections::HashMap<String, Configuration>,
}

impl ConfigurationFile {
    pub fn from_json(json: &str) -> Result<Self, ConfigurationError> {
        serde_json::from_str(json).map_err(|e| ConfigurationError::ParseError(e.to_string()))
    }

    pub fn get(&self, name: &str) -> Result<&Configuration, ConfigurationError> {
        self.configurations
            .get(name)
            .ok_or_else(|| ConfigurationError::NotFound(name.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_json() {
        let json = r#"{"configurations":{"ssn":{"engine":"ff1","alphabet":"alphanumeric","key_ref":"primary","header":"ssn"},"card":{"engine":"ff3","alphabet":"digits","key_ref":"payment"}}}"#;
        let cf = ConfigurationFile::from_json(json).unwrap();
        assert_eq!(cf.configurations.len(), 2);
        let ssn = cf.get("ssn").unwrap();
        assert_eq!(ssn.engine, "ff1");
        assert_eq!(ssn.header.as_deref(), Some("ssn"));
    }
}
