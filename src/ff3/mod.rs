pub mod core;

pub use self::core::{FF3, FF3Error};

/// Convenience: FF3 cipher over digits (radix 10)
pub fn digits(key: &[u8], tweak: &[u8]) -> Result<FF3, FF3Error> {
    FF3::new(key, tweak, crate::alphabet::digits())
}

/// Convenience: FF3 cipher over alphanumeric lowercase (radix 36)
/// Note: this is radix 36 (digits + lowercase), NOT radix 62.
pub fn alphanumeric_lower(key: &[u8], tweak: &[u8]) -> Result<FF3, FF3Error> {
    FF3::new(key, tweak, crate::alphabet::alphanumeric_lower())
}

/// Convenience: FF3 cipher over full alphanumeric (radix 62)
pub fn alphanumeric(key: &[u8], tweak: &[u8]) -> Result<FF3, FF3Error> {
    FF3::new(key, tweak, crate::alphabet::alphanumeric())
}
