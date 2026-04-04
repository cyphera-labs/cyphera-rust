// FF3-1 core implementation
// TODO: port from fpe-arena/implementations/rust/src/core.rs

use cyphera_alphabet::Alphabet;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FF3Error {
    #[error("invalid key length: {0} (expected 16, 24, or 32)")]
    InvalidKeyLength(usize),
    #[error("invalid tweak length: {0} (expected 8)")]
    InvalidTweakLength(usize),
    #[error("plaintext too short (min 2 characters)")]
    PlaintextTooShort,
    #[error("plaintext too long")]
    PlaintextTooLong,
    #[error("alphabet error: {0}")]
    Alphabet(#[from] cyphera_alphabet::AlphabetError),
}

pub struct FF3 {
    _key: Vec<u8>,
    _tweak: Vec<u8>,
    _alphabet: Alphabet,
}

impl FF3 {
    pub fn new(key: &[u8], tweak: &[u8], alphabet: Alphabet) -> Result<Self, FF3Error> {
        match key.len() {
            16 | 24 | 32 => {}
            n => return Err(FF3Error::InvalidKeyLength(n)),
        }
        if tweak.len() != 8 {
            return Err(FF3Error::InvalidTweakLength(tweak.len()));
        }
        Ok(Self {
            _key: key.to_vec(),
            _tweak: tweak.to_vec(),
            _alphabet: alphabet,
        })
    }

    pub fn encrypt(&self, _plaintext: &str) -> Result<String, FF3Error> {
        // TODO: port FF3-1 Feistel rounds from fpe-arena
        todo!("FF3-1 encrypt — port from fpe-arena")
    }

    pub fn decrypt(&self, _ciphertext: &str) -> Result<String, FF3Error> {
        // TODO: port FF3-1 Feistel rounds from fpe-arena
        todo!("FF3-1 decrypt — port from fpe-arena")
    }
}
