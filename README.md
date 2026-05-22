# cyphera

[![CI](https://github.com/cyphera-labs/cyphera-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/cyphera-labs/cyphera-rust/actions/workflows/ci.yml)
[![Security](https://github.com/cyphera-labs/cyphera-rust/actions/workflows/codeql.yml/badge.svg)](https://github.com/cyphera-labs/cyphera-rust/actions/workflows/codeql.yml)
[![crates.io](https://img.shields.io/crates/v/cyphera)](https://crates.io/crates/cyphera)
[![crates.io downloads](https://img.shields.io/crates/d/cyphera)](https://crates.io/crates/cyphera)
[![Rust](https://img.shields.io/badge/rust-2021%20edition-orange)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

Data protection SDK for Rust — format-preserving encryption (FF1/FF3), AES-GCM, data masking, and hashing.

## Install

```toml
[dependencies]
cyphera = "0.0.2-alpha.1"
```

Available on [crates.io](https://crates.io/crates/cyphera).

## Usage

```rust
use cyphera::Client;

// Load from a JSON configuration file
let client = Client::from_file("cyphera.json", Box::new(provider))?;

// Protect
let result = client.protect("ssn", "123-45-6789")?;
// result.output = "T01i6J-xF-07pX" (DPH-prefixed, dashes preserved)

// Access — single 1-arg method; the SDK uses the header to figure out the configuration
let plain = client.access(&result.output)?;
// plain.output = "123-45-6789"
```

## Configuration File (cyphera.json)

```json
{
  "configurations": {
    "ssn": { "engine": "ff1", "key_ref": "my-key", "header": "T01" }
  },
  "keys": {
    "my-key": { "material": "2B7E151628AED2A6ABF7158809CF4F3C" }
  }
}
```

The `header` (Data Protection Header, DPH) is a short prefix prepended to
protected output that identifies the configuration used. It lets
`access()` reverse a value without the caller naming the configuration.

## Cross-Language Compatible

All SDKs produce identical output for the same inputs:

```
Input:       123-45-6789
Java:        T01i6J-xF-07pX
Rust:        T01i6J-xF-07pX
Node:        T01i6J-xF-07pX
Python:      T01i6J-xF-07pX
Go:          T01i6J-xF-07pX
.NET:        T01i6J-xF-07pX
```

## Status

Alpha. API is unstable. Cross-language test vectors validated against Java, Node, Python, Go, and .NET implementations.

## License

Apache 2.0 — Copyright 2026 Horizon Digital Engineering LLC
