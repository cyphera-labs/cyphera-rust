use cyphera_alphabet::Alphabet;

/// Extract encryptable characters from input, preserving structural chars.
/// Returns (extracted_string, template) where template tracks positions.
///
/// Example: "123-45-6789" with digits alphabet
///   → extracted: "123456789", template: [E,E,E,S('-'),E,E,S('-'),E,E,E,E]
pub fn extract(input: &str, alphabet: &Alphabet) -> (String, Vec<TemplateChar>) {
    let mut extracted = String::new();
    let mut template = Vec::new();

    for c in input.chars() {
        if alphabet.contains(c) {
            extracted.push(c);
            template.push(TemplateChar::Encrypted);
        } else {
            template.push(TemplateChar::Structural(c));
        }
    }

    (extracted, template)
}

/// Reconstruct formatted output from encrypted characters and template.
///
/// Example: encrypted "r8n3w5j2m", template from "123-45-6789"
///   → "r8n-3w-5j2m"
pub fn reconstruct(encrypted: &str, template: &[TemplateChar]) -> String {
    let mut result = String::new();
    let mut enc_chars = encrypted.chars();

    for tc in template {
        match tc {
            TemplateChar::Encrypted => {
                if let Some(c) = enc_chars.next() {
                    result.push(c);
                }
            }
            TemplateChar::Structural(c) => {
                result.push(*c);
            }
        }
    }

    result
}

#[derive(Debug, Clone)]
pub enum TemplateChar {
    Encrypted,
    Structural(char),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ssn() {
        let alpha = cyphera_alphabet::alphanumeric_lower();
        let (extracted, template) = extract("123-45-6789", &alpha);
        assert_eq!(extracted, "123456789");
        assert_eq!(template.len(), 11); // 9 digits + 2 dashes
    }

    #[test]
    fn test_reconstruct_ssn() {
        let alpha = cyphera_alphabet::alphanumeric_lower();
        let (_, template) = extract("123-45-6789", &alpha);
        let result = reconstruct("r8n3w5j2m", &template);
        assert_eq!(result, "r8n-3w-5j2m");
    }

    #[test]
    fn test_roundtrip_format() {
        let alpha = cyphera_alphabet::alphanumeric_lower();
        let input = "4111-1111-1111-1111";
        let (extracted, template) = extract(input, &alpha);
        assert_eq!(extracted, "4111111111111111");
        let fake_encrypted = "k7m2x9p4n3w5j8r6";
        let result = reconstruct(fake_encrypted, &template);
        assert_eq!(result, "k7m2-x9p4-n3w5-j8r6");
    }

    #[test]
    fn test_phone_format() {
        let alpha = cyphera_alphabet::alphanumeric_lower();
        let (extracted, template) = extract("(555) 867-5309", &alpha);
        assert_eq!(extracted, "5558675309");
        let result = reconstruct("k7m2x9p4n3", &template);
        assert_eq!(result, "(k7m) 2x9-p4n3");
    }

    #[test]
    fn test_date_format() {
        let alpha = cyphera_alphabet::alphanumeric_lower();
        let (extracted, template) = extract("03/15/1990", &alpha);
        assert_eq!(extracted, "03151990");
        let result = reconstruct("p3x8n5k2", &template);
        assert_eq!(result, "p3/x8/n5k2");
    }

    #[test]
    fn test_no_structural() {
        let alpha = cyphera_alphabet::alphanumeric_lower();
        let (extracted, template) = extract("hello", &alpha);
        assert_eq!(extracted, "hello");
        let result = reconstruct("k7m2x", &template);
        assert_eq!(result, "k7m2x");
    }
}
