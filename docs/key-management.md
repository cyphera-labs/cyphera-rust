# Key Management

Cyphera separates key management from encryption. Your application never handles raw key bytes directly — a key provider resolves named references to key material.

## Key Provider Trait

```rust
pub trait KeyProvider: Send + Sync {
    fn resolve(&self, key_ref: &str) -> Result<KeyRecord, KeyError>;
    fn resolve_version(&self, key_ref: &str, version: u32) -> Result<KeyRecord, KeyError>;
}
```

Implement this trait for your key storage. Cyphera ships with providers for AWS KMS, GCP Cloud KMS, Azure Key Vault, HashiCorp Vault, and an in-memory provider for development.

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

## Built-in Providers

### AWS KMS

```rust
use cyphera_keys_aws::AwsKmsProvider;

let provider = AwsKmsProvider::new(AwsKmsConfig {
    key_arn: "arn:aws:kms:us-east-1:123456789:key/...",
    region: "us-east-1",
})?;
```

### GCP Cloud KMS

```rust
use cyphera_keys_gcp::GcpKmsProvider;

let provider = GcpKmsProvider::new(GcpKmsConfig {
    key_name: "projects/my-project/locations/us/keyRings/my-ring/cryptoKeys/my-key",
})?;
```

### Azure Key Vault

```rust
use cyphera_keys_azure::AzureKeyVaultProvider;

let provider = AzureKeyVaultProvider::new(AzureConfig {
    vault_url: "https://my-vault.vault.azure.net/",
    key_name: "my-key",
})?;
```

### HashiCorp Vault

```rust
use cyphera_keys_vault::VaultTransitProvider;

let provider = VaultTransitProvider::new(VaultConfig {
    address: "https://vault.example.com:8200",
    token: std::env::var("VAULT_TOKEN")?,
    mount: "transit",
    key_name: "my-key",
})?;
```

### Memory (dev/test only)

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
```

All providers implement the same `KeyProvider` trait. Swap providers without changing your encryption code.

## Writing a Custom Provider

If you use a key store we don't ship with, implement the trait:

```rust
use cyphera::keys::{KeyProvider, KeyRecord, KeyError};

struct MyProvider { /* ... */ }

impl KeyProvider for MyProvider {
    fn resolve(&self, key_ref: &str) -> Result<KeyRecord, KeyError> {
        // Resolve the active key version from your store
        todo!()
    }

    fn resolve_version(&self, key_ref: &str, version: u32) -> Result<KeyRecord, KeyError> {
        // Resolve a specific version (for decrypting old data)
        todo!()
    }
}
```

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
