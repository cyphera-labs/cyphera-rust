pub mod alphabet;
pub mod ff1;
pub mod ff3;
pub mod aes_gcm;
pub mod mask;
pub mod hash;
pub mod keys;
pub mod policy;
pub mod audit;
mod client;
mod format;

#[cfg(feature = "keychain")]
pub mod keychain_bridge;

pub use client::{Client, ClientBuilder, CypheraError, ProtectResult};

#[cfg(feature = "keychain")]
pub use keychain_bridge::KeychainProvider;

pub use keys::{KeyProvider, KeyRecord, KeyStatus, MemoryProvider};
pub use policy::{PolicyFile, PolicyEntry};
pub use audit::{AuditEvent, AuditLogger, NoopLogger, StdoutLogger};
