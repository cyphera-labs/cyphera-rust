pub mod core;

pub use self::core::{FF3, FF3Error};

/// Convenience: FF3 cipher over digits (radix 10)
pub fn digits(key: &[u8], tweak: &[u8]) -> Result<FF3, FF3Error> {
    FF3::new(key, tweak, cyphera_alphabet::digits())
}

/// Convenience: FF3 cipher over alphanumeric lowercase (radix 36)
pub fn alphanumeric(key: &[u8], tweak: &[u8]) -> Result<FF3, FF3Error> {
    FF3::new(key, tweak, cyphera_alphabet::alphanumeric_lower())
}
