# cyphera

Data obfuscation SDK for Rust. FPE, AES, masking, hashing — configured through policy files.

```rust
use cyphera::Client;

let client = Client::with_defaults(key, tweak);

let encrypted = client.protect("ssn", "123-45-6789")?;
// → "r8n-3w-5j2m" (dashes preserved)

let original = client.access("ssn", &encrypted.output)?;
// → "123-45-6789"
```

## Status

Early development. Core engines working with NIST test vectors.

## Docs

- [Getting Started](docs/getting-started.md)
- [Policy Reference](docs/policy-reference.md)
- [Key Management](docs/key-management.md)

## License

Apache 2.0
