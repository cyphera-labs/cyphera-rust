# Policy File Reference

Cyphera uses a YAML or JSON policy file to configure how data is protected. Each named policy defines an engine, alphabet, and key reference.

## Format

```yaml
policies:
  <policy-name>:
    engine: <engine>
    alphabet: <alphabet>      # optional, defaults to alphanumeric
    key_ref: <key-reference>  # optional for mask, required for encrypt/hash
    tag: <tag>                # optional, for ciphertext tagging
    mode: <mode>              # optional, "deterministic" (default) or "salted"
```

## Example

```yaml
policies:
  # Encrypt SSN — alphanumeric output, dashes preserved
  ssn:
    engine: ff1
    alphabet: alphanumeric
    key_ref: customer-primary

  # Encrypt credit card numbers
  card:
    engine: ff1
    alphabet: alphanumeric
    key_ref: payment-key

  # Mask SSN for display — show last 4
  ssn_display:
    engine: mask
    alphabet: last4

  # Hash SSN for analytics — deterministic token
  ssn_token:
    engine: hash
    key_ref: hmac-key

  # Encrypt date of birth
  dob:
    engine: ff1
    key_ref: customer-primary

  # Encrypt with digits-only output (when you absolutely need numeric)
  legacy_id:
    engine: ff1
    alphabet: digits
    key_ref: legacy-key
```

## Fields

### `engine` (required)

| Value | Type | Reversible | Description |
|-------|------|-----------|-------------|
| `ff1` | FPE | Yes | NIST SP 800-38G FF1. Recommended default. |
| `ff3` | FPE | Yes | NIST SP 800-38G Rev 1 FF3-1. |
| `mask` | Mask | No | Pattern-based redaction. |
| `hash` | Hash | No | HMAC-SHA256 deterministic token. |

### `alphabet` (optional)

For encryption engines (`ff1`, `ff3`):

| Value | Characters | Radix |
|-------|-----------|-------|
| `alphanumeric` | `0-9a-z` | 36 |
| `alphanumeric_full` | `0-9a-zA-Z` | 62 |
| `digits` | `0-9` | 10 |
| `hex` | `0-9a-f` | 16 |

Default: `alphanumeric` (recommended — higher radix = more security).

For mask engine, `alphabet` specifies the mask pattern:

| Value | Effect |
|-------|--------|
| `last4` / `last_4` | Show last 4 characters |
| `last6` / `last_6` | Show last 6 characters |
| `first4` / `first_4` | Show first 4 characters |
| `first6` / `first_6` | Show first 6 characters |
| `full` | Mask everything (preserve structural chars) |

### `key_ref` (required for ff1/ff3/hash)

The name of the key to resolve from your key provider. Not needed for mask.

### `tag` (optional)

A short identifier for ciphertext tagging. When set, allows self-describing ciphertext — the receiver can identify which policy was used without prior knowledge.

### `mode` (optional)

| Value | Description |
|-------|-------------|
| `deterministic` | Same input + same key = same output. Enables joins, dedup, search. **(default)** |
| `salted` | Random salt per operation. Different output each time. Higher security, no referential integrity. |

## Multiple Policies for the Same Data

A common pattern is defining multiple policies for the same data type, each for a different use case:

```yaml
policies:
  # Full encryption — for storage
  ssn:
    engine: ff1
    key_ref: primary

  # Partial mask — for support agents
  ssn_support:
    engine: mask
    alphabet: last4

  # Full mask — for viewers
  ssn_hidden:
    engine: mask
    alphabet: full

  # Deterministic hash — for analytics joins
  ssn_analytics:
    engine: hash
    key_ref: hmac-key
```

Your application maps the user's role to the right policy name:

```rust
let policy = match user_role {
    "compliance" => "ssn",           // full decrypt
    "support"    => "ssn_support",   // see last 4
    "analyst"    => "ssn_analytics", // deterministic token
    _            => "ssn_hidden",    // see nothing
};

let result = client.protect(policy, ssn_value)?;
```

## Loading

```rust
// From file
let client = Client::from_policy_file("cyphera.yaml", key_provider)?;

// From string
let pf = PolicyFile::from_yaml(yaml_string)?;
let client = Client::from_policy(pf, key_provider);

// From JSON
let pf = PolicyFile::from_json(json_string)?;
```
