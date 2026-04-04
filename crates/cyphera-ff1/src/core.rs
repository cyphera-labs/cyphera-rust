use cyphera_alphabet::Alphabet;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FF1Error {
    #[error("invalid key length: {0} (expected 16, 24, or 32)")]
    InvalidKeyLength(usize),
    #[error("plaintext too short (min 2 characters)")]
    PlaintextTooShort,
    #[error("alphabet error: {0}")]
    Alphabet(#[from] cyphera_alphabet::AlphabetError),
}

pub struct FF1 {
    _key: Vec<u8>,
    _tweak: Vec<u8>,
    _alphabet: Alphabet,
}

impl FF1 {
    pub fn new(key: &[u8], tweak: &[u8], alphabet: Alphabet) -> Result<Self, FF1Error> {
        match key.len() {
            16 | 24 | 32 => {}
            n => return Err(FF1Error::InvalidKeyLength(n)),
        }
        Ok(Self {
            _key: key.to_vec(),
            _tweak: tweak.to_vec(),
            _alphabet: alphabet,
        })
    }

    pub fn encrypt(&self, _plaintext: &str) -> Result<String, FF1Error> {
        todo!("FF1 encrypt — 10-round Feistel with AES-CBC PRF")
    }

    pub fn decrypt(&self, _ciphertext: &str) -> Result<String, FF1Error> {
        todo!("FF1 decrypt")
    }
}
