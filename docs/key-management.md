# Key Management

Cyphera separates key management from encryption. Your application never handles raw key bytes directly — a key provider resolves named references to key material.

## Key Provider Trait

```rust
pub trait KeyProvider: Send + Sync {
    fn resolve(&self, key_ref: &str) -> Result<KeyRecord, KeyError>;
    fn resolve_version(&self, key_ref: &str, version: u32) -> Result<KeyRecord, KeyError>;
}
```

Implement this trait for your key storage. Cyphera ships with built-in providers for development, and you can write your own for production (KMS, Vault, etc.).

## Built-in: Memory Provider

For development, testing, and quick starts:

```rust
use cyphera::{MemoryProvider, KeyRecord, KeyStatus};

let provider = MemoryProvider::new(vec![
    KeyRecord {
        key_ref: "primary".into(),
        version: 1,
        status: KeyStatus::Active,
        material: key_bytes.to_vec(),
        tweak: tweak_bytes.to_vec(),
    },
]);

let client = Client::from_policy_file("cyphera.yaml", Box::new(provider))?;
```

## Key Versioning

Keys have versions and statuses for rotation:

```rust
let provider = MemoryProvider::new(vec![
    // Old key — can still decrypt old ciphertext
    KeyRecord {
        key_ref: "primary".into(),
        version: 1,
        status: KeyStatus::Deprecated,
        material: old_key.to_vec(),
        tweak: old_tweak.to_vec(),
    },
    // Current key — used for new encryption
    KeyRecord {
        key_ref: "primary".into(),
        version: 2,
        status: KeyStatus::Active,
        material: new_key.to_vec(),
        tweak: new_tweak.to_vec(),
    },
]);
```

### Key Status Lifecycle

```
Active → Deprecated → Disabled
  │          │            │
  │          │            └── Cannot encrypt or decrypt
  │          └─────────────── Can decrypt, cannot encrypt (TODO)
  └────────────────────────── Can encrypt and decrypt
```

- `resolve()` returns the latest `Active` version (for encryption)
- `resolve_version()` returns a specific version (for decrypting old ciphertext)

## Writing a Custom Provider

For production, implement `KeyProvider` to talk to your key management system:

```rust
use cyphera::keys::{KeyProvider, KeyRecord, KeyError};

struct AwsKmsProvider {
    // your AWS SDK client, key ARN, etc.
}

impl KeyProvider for AwsKmsProvider {
    fn resolve(&self, key_ref: &str) -> Result<KeyRecord, KeyError> {
        // Call AWS KMS to unwrap the data encryption key
        // Return the unwrapped key material
        todo!()
    }

    fn resolve_version(&self, key_ref: &str, version: u32) -> Result<KeyRecord, KeyError> {
        // Resolve a specific key version
        todo!()
    }
}
```

The same pattern works for GCP KMS, Azure Key Vault, HashiCorp Vault, or any other secret store. Cyphera doesn't care where the key comes from — just that it arrives via the `KeyProvider` trait.

## Key Requirements

| Engine | Key length | Tweak length |
|--------|-----------|-------------|
| FF1 | 16, 24, or 32 bytes | Any length (can be empty) |
| FF3 | 16, 24, or 32 bytes | Exactly 8 bytes |
| Hash (HMAC) | Any length (32+ recommended) | N/A |

## Security Notes

- Never hardcode keys in source code. Use environment variables, secret managers, or KMS.
- The `MemoryProvider` is for dev/test only.
- Key material is held in memory while the provider is alive. For production, consider providers that unwrap keys on demand and clear them after use.
- Cyphera never logs key material in audit events.
