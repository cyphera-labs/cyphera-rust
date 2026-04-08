use thiserror::Error;

#[derive(Error, Debug)]
pub enum AesError {
    #[error("invalid key length: {0} (expected 32)")]
    InvalidKeyLength(usize),
    #[error("decryption failed")]
    DecryptionFailed,
}

pub fn encrypt(_key: &[u8], _plaintext: &[u8]) -> Result<Vec<u8>, AesError> {
    todo!("AES-256-GCM encrypt")
}

pub fn decrypt(_key: &[u8], _ciphertext: &[u8]) -> Result<Vec<u8>, AesError> {
    todo!("AES-256-GCM decrypt")
}
