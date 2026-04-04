// FF3-1 Format-Preserving Encryption (NIST SP 800-38G Rev 1)
// Based on fpe-arena Rust implementation

use cyphera_alphabet::Alphabet;

mod core;

pub use self::core::{FF3, FF3Error};

/// Convenience: create an FF3 cipher with the given key and tweak over digits (radix 10)
pub fn digits(key: &[u8], tweak: &[u8]) -> Result<FF3, FF3Error> {
    FF3::new(key, tweak, cyphera_alphabet::digits())
}

/// Convenience: create an FF3 cipher over alphanumeric lowercase (radix 36)
pub fn alphanumeric(key: &[u8], tweak: &[u8]) -> Result<FF3, FF3Error> {
    FF3::new(key, tweak, cyphera_alphabet::alphanumeric_lower())
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {
        // NIST test vectors go here
    }
}
