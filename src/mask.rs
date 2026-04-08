use thiserror::Error;

#[derive(Error, Debug)]
pub enum MaskError {
    #[error("input too short for pattern '{0}'")]
    InputTooShort(String),
}

pub fn last_n(input: &str, n: usize, mask_char: char) -> String {
    let chars: Vec<char> = input.chars().collect();
    if chars.len() <= n {
        return input.to_string();
    }
    let masked: String = chars[..chars.len() - n].iter().map(|_| mask_char).collect();
    let visible: String = chars[chars.len() - n..].iter().collect();
    format!("{masked}{visible}")
}

pub fn first_n(input: &str, n: usize, mask_char: char) -> String {
    let chars: Vec<char> = input.chars().collect();
    if chars.len() <= n {
        return input.to_string();
    }
    let visible: String = chars[..n].iter().collect();
    let masked: String = chars[n..].iter().map(|_| mask_char).collect();
    format!("{visible}{masked}")
}

pub fn full(input: &str, mask_char: char) -> String {
    input.chars().map(|_| mask_char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_last_4() {
        assert_eq!(last_n("123-45-6789", 4, '*'), "*******6789");
    }

    #[test]
    fn test_first_3() {
        assert_eq!(first_n("123456789", 3, '*'), "123******");
    }

    #[test]
    fn test_full_masks_everything() {
        assert_eq!(full("123-45-6789", '*'), "***********");
    }
}
