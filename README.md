# cyphera

Data protection SDK for Rust — format-preserving encryption (FF1/FF3), AES-GCM, data masking, and hashing.

## Install

```toml
[dependencies]
cyphera = "0.0.1-alpha.2"
```

Available on [crates.io](https://crates.io/crates/cyphera).

## Usage

```rust
use cyphera::Client;

// Load from a JSON policy file
let client = Client::from_file("cyphera.json", Box::new(provider))?;

// Protect
let result = client.protect("ssn", "123-45-6789")?;
// result.output = "T01i6J-xF-07pX" (tagged, dashes preserved)

// Access (tag-based, no policy name needed)
let plain = client.access_by_tag(&result.output)?;
// plain.output = "123-45-6789"
```

## Policy File (cyphera.json)

```json
{
  "policies": {
    "ssn": { "engine": "ff1", "key_ref": "my-key", "tag": "T01" }
  },
  "keys": {
    "my-key": { "material": "2B7E151628AED2A6ABF7158809CF4F3C" }
  }
}
```

## Cross-Language Compatible

Java, Rust, and Node produce identical output for the same inputs:

```
Input:       123-45-6789
Java:        T01i6J-xF-07pX
Rust:        T01i6J-xF-07pX
Node:        T01i6J-xF-07pX
```

## Status

Alpha. API is unstable. Cross-language test vectors validated against Java and Node implementations.

## License

Apache 2.0 — Copyright 2026 Horizon Digital Engineering LLC
