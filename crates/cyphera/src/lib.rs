// Cyphera SDK — the main entry point
//
// Users import `cyphera` and get access to everything:
//   use cyphera::Client;
//
// Primitives are available directly if needed:
//   use cyphera_ff1::FF1;
//   use cyphera_ff3::FF3;

pub use cyphera_alphabet as alphabet;
pub use cyphera_audit as audit;
pub use cyphera_keys as keys;
pub use cyphera_policy as policy;

// Re-export primitives
pub use cyphera_ff1;
pub use cyphera_ff3;
pub use cyphera_aes;
pub use cyphera_mask as mask;
pub use cyphera_hash as hash;

pub use thiserror::Error;

#[derive(Error, Debug)]
pub enum CypheraError {
    #[error("policy error: {0}")]
    Policy(#[from] cyphera_policy::PolicyError),
    #[error("key error: {0}")]
    Key(#[from] cyphera_keys::KeyError),
    #[error("unknown engine: {0}")]
    UnknownEngine(String),
    #[error("operation not supported: {0}")]
    Unsupported(String),
}

// Client will be built here once the primitives are working
