use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("policy not found: {0}")]
    NotFound(String),
    #[error("failed to parse policy file: {0}")]
    ParseError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEntry {
    pub engine: String,
    pub alphabet: Option<String>,
    pub key_ref: Option<String>,
    pub tag: Option<String>,
    #[serde(default = "default_tag_enabled")]
    pub tag_enabled: bool,
    #[serde(default = "default_tag_length")]
    pub tag_length: usize,
    pub mode: Option<String>,
    pub pattern: Option<String>,     // for mask engine
    pub algorithm: Option<String>,   // for hash engine
}

fn default_tag_enabled() -> bool { true }
fn default_tag_length() -> usize { 3 }

impl PolicyEntry {
    pub fn is_reversible(&self) -> bool {
        matches!(self.engine.as_str(), "ff1" | "ff3" | "aes_gcm")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFile {
    pub policies: std::collections::HashMap<String, PolicyEntry>,
}

impl PolicyFile {
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        serde_yaml::from_str(yaml).map_err(|e| PolicyError::ParseError(e.to_string()))
    }

    pub fn from_json(json: &str) -> Result<Self, PolicyError> {
        serde_json::from_str(json).map_err(|e| PolicyError::ParseError(e.to_string()))
    }

    pub fn get(&self, name: &str) -> Result<&PolicyEntry, PolicyError> {
        self.policies
            .get(name)
            .ok_or_else(|| PolicyError::NotFound(name.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_yaml() {
        let yaml = r#"
policies:
  ssn:
    engine: ff1
    alphabet: alphanumeric
    key_ref: primary
    tag: ssn
  card:
    engine: ff3
    alphabet: digits
    key_ref: payment
"#;
        let pf = PolicyFile::from_yaml(yaml).unwrap();
        assert_eq!(pf.policies.len(), 2);
        let ssn = pf.get("ssn").unwrap();
        assert_eq!(ssn.engine, "ff1");
        assert_eq!(ssn.tag.as_deref(), Some("ssn"));
    }
}
