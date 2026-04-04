use thiserror::Error;

#[derive(Error, Debug)]
pub enum AlphabetError {
    #[error("character '{0}' not in alphabet")]
    InvalidChar(char),
    #[error("empty alphabet")]
    Empty,
    #[error("duplicate character '{0}' in alphabet")]
    Duplicate(char),
}

#[derive(Debug, Clone)]
pub struct Alphabet {
    chars: Vec<char>,
}

impl Alphabet {
    pub fn new(chars: &str) -> Result<Self, AlphabetError> {
        let chars: Vec<char> = chars.chars().collect();
        if chars.is_empty() {
            return Err(AlphabetError::Empty);
        }
        // Check for duplicates
        let mut seen = std::collections::HashSet::new();
        for &c in &chars {
            if !seen.insert(c) {
                return Err(AlphabetError::Duplicate(c));
            }
        }
        Ok(Self { chars })
    }

    pub fn radix(&self) -> usize {
        self.chars.len()
    }

    pub fn char_at(&self, index: usize) -> char {
        self.chars[index]
    }

    pub fn index_of(&self, c: char) -> Result<usize, AlphabetError> {
        self.chars
            .iter()
            .position(|&ch| ch == c)
            .ok_or(AlphabetError::InvalidChar(c))
    }

    pub fn chars(&self) -> &[char] {
        &self.chars
    }

    /// Is this character part of the alphabet (encrypted) or structural (preserved)?
    pub fn contains(&self, c: char) -> bool {
        self.chars.contains(&c)
    }
}

// Built-in alphabets — all "non-exploding" safe characters
pub fn digits() -> Alphabet {
    Alphabet::new("0123456789").unwrap()
}

pub fn hex_lower() -> Alphabet {
    Alphabet::new("0123456789abcdef").unwrap()
}

pub fn alphanumeric_lower() -> Alphabet {
    Alphabet::new("0123456789abcdefghijklmnopqrstuvwxyz").unwrap()
}

pub fn alphanumeric() -> Alphabet {
    Alphabet::new("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digits() {
        let a = digits();
        assert_eq!(a.radix(), 10);
        assert_eq!(a.char_at(0), '0');
        assert_eq!(a.index_of('9').unwrap(), 9);
    }

    #[test]
    fn test_alphanumeric_lower() {
        let a = alphanumeric_lower();
        assert_eq!(a.radix(), 36);
    }

    #[test]
    fn test_contains() {
        let a = digits();
        assert!(a.contains('5'));
        assert!(!a.contains('-'));
        assert!(!a.contains('a'));
    }

    #[test]
    fn test_duplicate_rejected() {
        assert!(Alphabet::new("aab").is_err());
    }

    #[test]
    fn test_empty_rejected() {
        assert!(Alphabet::new("").is_err());
    }
}
