# cyphera

Data protection SDK for Rust — format-preserving encryption (FF1/FF3), AES-GCM, data masking, and hashing.

## Install

```toml
[dependencies]
cyphera = "0.0.1-alpha.1"
```

## Usage

```rust
use cyphera::{Client, PolicyFile, MemoryProvider, KeyRecord, KeyStatus};

let yaml = r#"
policies:
  ssn:
    engine: ff1
    key_ref: my-key
    tag: T01
"#;

let pf = PolicyFile::from_yaml(yaml).unwrap();
let provider = MemoryProvider::new(vec![
    KeyRecord {
        key_ref: "my-key".into(),
        version: 1,
        status: KeyStatus::Active,
        material: hex::decode("2B7E151628AED2A6ABF7158809CF4F3C").unwrap(),
        tweak: vec![],
    },
]);

let client = Client::from_policy(pf, Box::new(provider)).unwrap();

// Protect
let result = client.protect("ssn", "123-45-6789").unwrap();
// result.output = "T01k7R-m2-9xPq" (tagged, dashes preserved)

// Access (tag-based, no policy name needed)
let plain = client.access_by_tag(&result.output).unwrap();
assert_eq!(plain.output, "123-45-6789");
```

## Status

Alpha. API is unstable. Cross-language test vectors validated against Java implementation.

## License

Apache 2.0
