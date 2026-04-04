pub mod core;

pub use self::core::{FF1, FF1Error};

/// Convenience: FF1 cipher over digits (radix 10)
pub fn digits(key: &[u8], tweak: &[u8]) -> Result<FF1, FF1Error> {
    FF1::new(key, tweak, cyphera_alphabet::digits())
}

/// Convenience: FF1 cipher over alphanumeric lowercase (radix 36)
pub fn alphanumeric(key: &[u8], tweak: &[u8]) -> Result<FF1, FF1Error> {
    FF1::new(key, tweak, cyphera_alphabet::alphanumeric_lower())
}
