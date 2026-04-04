// FF1 Format-Preserving Encryption (NIST SP 800-38G)
// TODO: implement or port from existing FF1 Rust implementations

use cyphera_alphabet::Alphabet;

mod core;

pub use self::core::{FF1, FF1Error};

/// Convenience: create an FF1 cipher with the given key and tweak over digits (radix 10)
pub fn digits(key: &[u8], tweak: &[u8]) -> Result<FF1, FF1Error> {
    FF1::new(key, tweak, cyphera_alphabet::digits())
}

/// Convenience: create an FF1 cipher over alphanumeric lowercase (radix 36)
pub fn alphanumeric(key: &[u8], tweak: &[u8]) -> Result<FF1, FF1Error> {
    FF1::new(key, tweak, cyphera_alphabet::alphanumeric_lower())
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {
        // NIST test vectors go here
    }
}
