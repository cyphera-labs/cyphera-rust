pub mod core;

pub use self::core::{FF1, FF1Error};

/// Convenience: FF1 cipher over digits (radix 10)
pub fn digits(key: &[u8], tweak: &[u8]) -> Result<FF1, FF1Error> {
    FF1::new(key, tweak, crate::alphabet::digits())
}

/// Convenience: FF1 cipher over alphanumeric lowercase (radix 36)
/// Note: this is radix 36 (digits + lowercase), NOT radix 62.
/// For radix 62, use FF1::new() directly with crate::alphabet::alphanumeric().
pub fn alphanumeric_lower(key: &[u8], tweak: &[u8]) -> Result<FF1, FF1Error> {
    FF1::new(key, tweak, crate::alphabet::alphanumeric_lower())
}

/// Convenience: FF1 cipher over full alphanumeric (radix 62)
pub fn alphanumeric(key: &[u8], tweak: &[u8]) -> Result<FF1, FF1Error> {
    FF1::new(key, tweak, crate::alphabet::alphanumeric())
}
