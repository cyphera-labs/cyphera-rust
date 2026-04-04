use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub operation: String,
    pub policy: String,
    pub key_ref: Option<String>,
    pub key_version: Option<u32>,
    pub engine: String,
    pub success: bool,
    pub error: Option<String>,
    pub context: HashMap<String, String>,
    pub timestamp: String,
}

pub trait AuditLogger: Send + Sync {
    fn log(&self, event: &AuditEvent);
}

pub struct NoopLogger;
impl AuditLogger for NoopLogger {
    fn log(&self, _event: &AuditEvent) {}
}

pub struct StdoutLogger;
impl AuditLogger for StdoutLogger {
    fn log(&self, event: &AuditEvent) {
        if let Ok(json) = serde_json::to_string(event) {
            println!("{json}");
        }
    }
}
