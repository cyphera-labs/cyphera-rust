use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512, Digest};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

#[derive(Error, Debug)]
pub enum HashError {
    #[error("invalid key length")]
    InvalidKey,
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// HMAC-SHA256
pub fn hmac_sha256(key: &[u8], input: &str) -> Result<String, HashError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| HashError::InvalidKey)?;
    mac.update(input.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// HMAC-SHA384
pub fn hmac_sha384(key: &[u8], input: &str) -> Result<String, HashError> {
    let mut mac = HmacSha384::new_from_slice(key).map_err(|_| HashError::InvalidKey)?;
    mac.update(input.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// HMAC-SHA512
pub fn hmac_sha512(key: &[u8], input: &str) -> Result<String, HashError> {
    let mut mac = HmacSha512::new_from_slice(key).map_err(|_| HashError::InvalidKey)?;
    mac.update(input.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Plain SHA256 (no key)
pub fn sha256(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

/// Plain SHA384 (no key)
pub fn sha384(input: &str) -> String {
    hex::encode(Sha384::digest(input.as_bytes()))
}

/// Plain SHA512 (no key)
pub fn sha512(input: &str) -> String {
    hex::encode(Sha512::digest(input.as_bytes()))
}

/// Dispatch based on algorithm name. If key is provided, uses HMAC. Otherwise plain hash.
pub fn hash(algorithm: &str, key: Option<&[u8]>, input: &str) -> Result<String, HashError> {
    match (algorithm, key) {
        ("sha256" | "sha-256", Some(k)) => hmac_sha256(k, input),
        ("sha384" | "sha-384", Some(k)) => hmac_sha384(k, input),
        ("sha512" | "sha-512", Some(k)) => hmac_sha512(k, input),
        ("sha256" | "sha-256", None) => Ok(sha256(input)),
        ("sha384" | "sha-384", None) => Ok(sha384(input)),
        ("sha512" | "sha-512", None) => Ok(sha512(input)),
        (algo, _) => Err(HashError::UnsupportedAlgorithm(algo.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_deterministic() {
        let key = hex::decode("2B7E151628AED2A6ABF7158809CF4F3C").unwrap();
        let a = hmac_sha256(&key, "123-45-6789").unwrap();
        let b = hmac_sha256(&key, "123-45-6789").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_hmac_sha512_deterministic() {
        let key = hex::decode("2B7E151628AED2A6ABF7158809CF4F3C").unwrap();
        let a = hmac_sha512(&key, "123-45-6789").unwrap();
        let b = hmac_sha512(&key, "123-45-6789").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 128); // 64 bytes = 128 hex chars
    }

    #[test]
    fn test_plain_sha256() {
        let a = sha256("123-45-6789");
        let b = sha256("123-45-6789");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_dispatch() {
        let key = hex::decode("2B7E151628AED2A6ABF7158809CF4F3C").unwrap();
        let hmac = hash("sha256", Some(&key), "test").unwrap();
        let plain = hash("sha256", None, "test").unwrap();
        assert_ne!(hmac, plain); // HMAC and plain produce different output
    }
}
