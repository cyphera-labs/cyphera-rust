# Getting Started

## Install

```toml
# Cargo.toml
[dependencies]
cyphera = "0.1"
```

## Quick Start — No Config File

The fastest way to get running. Uses FF1 with alphanumeric output and built-in presets.

```rust
use cyphera::Client;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 16, 24, or 32 bytes (AES-128/192/256)
    let key = b"my-secret-key-32-bytes-long!!!!!";
    let tweak = &[0u8; 8];

    let client = Client::with_defaults(key, tweak);

    // Encrypt — structural characters (dashes, slashes) are preserved
    let result = client.encrypt("ssn", "123-45-6789")?;
    println!("Encrypted: {}", result.output);
    // → "r8n-3w-5j2m"

    // Decrypt
    let plain = client.decrypt("ssn", &result.output)?;
    println!("Decrypted: {}", plain.output);
    // → "123-45-6789"

    Ok(())
}
```

Built-in presets: `ssn`, `card`, `pan`, `phone`, `dob`, `name`, `address`, `general`. All use FF1 + alphanumeric by default.

## Policy File — The Recommended Way

Create a `cyphera.yaml`:

```yaml
policies:
  ssn:
    engine: ff1
    alphabet: alphanumeric
    key_ref: primary

  card:
    engine: ff1
    alphabet: alphanumeric
    key_ref: primary

  ssn_display:
    engine: mask
    alphabet: last4

  ssn_token:
    engine: hash
    key_ref: primary
```

Then load it:

```rust
use cyphera::{Client, MemoryProvider, KeyRecord, KeyStatus};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = MemoryProvider::new(vec![
        KeyRecord {
            key_ref: "primary".into(),
            version: 1,
            status: KeyStatus::Active,
            material: b"my-secret-key-32-bytes-long!!!!!".to_vec(),
            tweak: vec![0u8; 8],
        },
    ]);

    let client = Client::from_policy_file("cyphera.yaml", Box::new(provider))?;

    // Each policy name maps to a different engine/config
    let encrypted = client.encrypt("ssn", "123-45-6789")?;
    let masked = client.mask("123-45-6789", "last4")?;
    let hashed = client.hash("ssn", "123-45-6789")?;

    println!("Encrypted: {}", encrypted.output);  // "r8n-3w-5j2m"
    println!("Masked:    {}", masked.output);      // "*******6789"
    println!("Hashed:    {}", hashed.output);      // "a1b2c3d4..."

    Ok(())
}
```

## Protect / Access — Generic API

If you want the policy to decide the engine, use `protect()` and `access()`:

```rust
// Policy says engine: ff1 → encrypts
let r = client.protect("ssn", "123-45-6789")?;

// Policy says engine: mask → masks
let r = client.protect("ssn_display", "123-45-6789")?;

// Policy says engine: hash → hashes
let r = client.protect("ssn_token", "123-45-6789")?;

// Reverse (only works for reversible engines)
let plain = client.access("ssn", &encrypted.output)?;

// This errors — mask is irreversible
let err = client.access("ssn_display", &masked.output);
// → Error: cannot reverse 'ssn_display' — mask is irreversible
```

## Format Preservation

Cyphera automatically preserves structural characters. Only alphanumeric characters are encrypted — dashes, slashes, parentheses, spaces stay in place.

```
Input:     123-45-6789        →  Output:    r8n-3w-5j2m
Input:     4111-1111-1111-1111 → Output:    k7m2-x9p4-n3w5-j8r6
Input:     (555) 867-5309     →  Output:    (k7m) 2x9-p4n3
Input:     03/15/1990         →  Output:    p3/x8/n5k2
```

No schema changes. No column width changes. Fits wherever the original data did.

## Engines

| Engine | Reversible | Use case |
|--------|-----------|----------|
| `ff1` | Yes | Default. NIST SP 800-38G format-preserving encryption. |
| `ff3` | Yes | Alternative NIST FPE. |
| `mask` | No | Display redaction. Show last 4, first 6, etc. |
| `hash` | No | Deterministic tokens for joins/dedup. HMAC-SHA256. |

## Alphabets

| Name | Characters | Radix | Notes |
|------|-----------|-------|-------|
| `alphanumeric` | `0-9a-z` | 36 | **Default.** Secure, compact, non-exploding. |
| `alphanumeric_full` | `0-9a-zA-Z` | 62 | Case-sensitive variant. |
| `digits` | `0-9` | 10 | When output must be numeric. Lower security. |
| `hex` | `0-9a-f` | 16 | Hex output. |

## Batch Operations

```rust
let items = vec![
    ("ssn", "123-45-6789"),
    ("card", "4111-1111-1111-1111"),
    ("dob", "03/15/1990"),
];

let results = client.encrypt_batch(&items);

for r in results {
    let r = r?;
    println!("{}: {}", r.policy_name, r.output);
}
```
