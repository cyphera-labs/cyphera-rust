use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

#[derive(Error, Debug)]
pub enum HashError {
    #[error("invalid key length")]
    InvalidKey,
}

pub fn hmac_sha256(key: &[u8], input: &str) -> Result<String, HashError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| HashError::InvalidKey)?;
    mac.update(input.as_bytes());
    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic() {
        let key = b"test-key-for-hmac-operations!!!!" ;
        let a = hmac_sha256(key, "123-45-6789").unwrap();
        let b = hmac_sha256(key, "123-45-6789").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_different_inputs() {
        let key = b"test-key-for-hmac-operations!!!!";
        let a = hmac_sha256(key, "123-45-6789").unwrap();
        let b = hmac_sha256(key, "987-65-4321").unwrap();
        assert_ne!(a, b);
    }
}
