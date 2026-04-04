use aes::{Aes128, Aes192, Aes256, Block};
use aes::cipher::{BlockEncrypt, KeyInit};
use num_bigint::BigUint;
use num_traits::{Zero, One};
use num_integer::Integer;
use cyphera_alphabet::Alphabet;
use std::collections::HashMap;

#[derive(Debug)]
pub enum FF3Error {
    InvalidKeyLength(usize),
    InvalidTweakLength(usize),
    PlaintextTooShort,
    PlaintextTooLong,
    InvalidChar(char, usize),
    AlphabetError(cyphera_alphabet::AlphabetError),
}

impl std::fmt::Display for FF3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyLength(n) => write!(f, "invalid key length: {n} (expected 16, 24, or 32)"),
            Self::InvalidTweakLength(n) => write!(f, "invalid tweak length: {n} (expected 8)"),
            Self::PlaintextTooShort => write!(f, "plaintext too short (min 2 characters)"),
            Self::PlaintextTooLong => write!(f, "plaintext too long"),
            Self::InvalidChar(c, pos) => write!(f, "invalid char '{c}' at position {pos}"),
            Self::AlphabetError(e) => write!(f, "alphabet error: {e}"),
        }
    }
}

impl std::error::Error for FF3Error {}

impl From<cyphera_alphabet::AlphabetError> for FF3Error {
    fn from(e: cyphera_alphabet::AlphabetError) -> Self {
        Self::AlphabetError(e)
    }
}

/// Trait to abstract over different AES key sizes
trait AesEncryptor: Send + Sync {
    fn encrypt_block(&self, block: &mut Block);
}

struct Aes128Enc(Aes128);
struct Aes192Enc(Aes192);
struct Aes256Enc(Aes256);

impl AesEncryptor for Aes128Enc {
    fn encrypt_block(&self, block: &mut Block) { self.0.encrypt_block(block); }
}
impl AesEncryptor for Aes192Enc {
    fn encrypt_block(&self, block: &mut Block) { self.0.encrypt_block(block); }
}
impl AesEncryptor for Aes256Enc {
    fn encrypt_block(&self, block: &mut Block) { self.0.encrypt_block(block); }
}

/// FF3-1 Format-Preserving Encryption cipher
pub struct FF3 {
    radix: usize,
    aes_cipher: Box<dyn AesEncryptor>,
    tweak: Vec<u8>,
    min_len: usize,
    max_len: usize,
    alpha: Vec<char>,
    index: HashMap<char, usize>,
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

        let radix = alphabet.radix();
        let aes_cipher = Self::create_aes(key)?;
        let max_len = if radix <= 36 { 32 } else { 56 };

        let alpha: Vec<char> = alphabet.chars().to_vec();
        let index: HashMap<char, usize> = alpha.iter()
            .enumerate()
            .map(|(i, &c)| (c, i))
            .collect();

        Ok(Self {
            radix,
            aes_cipher,
            tweak: tweak.to_vec(),
            min_len: 2,
            max_len,
            alpha,
            index,
        })
    }

    fn create_aes(key: &[u8]) -> Result<Box<dyn AesEncryptor>, FF3Error> {
        let mut rev = key.to_vec();
        rev.reverse();
        match key.len() {
            16 => Ok(Box::new(Aes128Enc(Aes128::new_from_slice(&rev).unwrap()))),
            24 => Ok(Box::new(Aes192Enc(Aes192::new_from_slice(&rev).unwrap()))),
            32 => Ok(Box::new(Aes256Enc(Aes256::new_from_slice(&rev).unwrap()))),
            n => Err(FF3Error::InvalidKeyLength(n)),
        }
    }

    fn to_digits(&self, s: &str) -> Result<Vec<usize>, FF3Error> {
        s.chars()
            .enumerate()
            .map(|(i, c)| {
                self.index.get(&c)
                    .copied()
                    .ok_or(FF3Error::InvalidChar(c, i))
            })
            .collect()
    }

    fn from_digits(&self, digits: &[usize]) -> String {
        digits.iter().map(|&d| self.alpha[d]).collect()
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String, FF3Error> {
        let digits = self.to_digits(plaintext)?;
        let n = digits.len();
        if n < self.min_len { return Err(FF3Error::PlaintextTooShort); }
        if n > self.max_len { return Err(FF3Error::PlaintextTooLong); }
        let result = self.ff3_encrypt(&digits, &self.tweak);
        Ok(self.from_digits(&result))
    }

    pub fn decrypt(&self, ciphertext: &str) -> Result<String, FF3Error> {
        let digits = self.to_digits(ciphertext)?;
        let n = digits.len();
        if n < self.min_len { return Err(FF3Error::PlaintextTooShort); }
        if n > self.max_len { return Err(FF3Error::PlaintextTooLong); }
        let result = self.ff3_decrypt(&digits, &self.tweak);
        Ok(self.from_digits(&result))
    }

    pub fn encrypt_with_tweak(&self, plaintext: &str, additional_tweak: &[u8]) -> Result<String, FF3Error> {
        let digits = self.to_digits(plaintext)?;
        let n = digits.len();
        if n < self.min_len { return Err(FF3Error::PlaintextTooShort); }
        if n > self.max_len { return Err(FF3Error::PlaintextTooLong); }
        let tweak = self.combine_tweaks(additional_tweak);
        let result = self.ff3_encrypt(&digits, &tweak);
        Ok(self.from_digits(&result))
    }

    pub fn decrypt_with_tweak(&self, ciphertext: &str, additional_tweak: &[u8]) -> Result<String, FF3Error> {
        let digits = self.to_digits(ciphertext)?;
        let n = digits.len();
        if n < self.min_len { return Err(FF3Error::PlaintextTooShort); }
        if n > self.max_len { return Err(FF3Error::PlaintextTooLong); }
        let tweak = self.combine_tweaks(additional_tweak);
        let result = self.ff3_decrypt(&digits, &tweak);
        Ok(self.from_digits(&result))
    }

    // ── Core FF3 algorithm ──────────────────────────────────────────────

    fn ff3_encrypt(&self, plaintext: &[usize], tweak: &[u8]) -> Vec<usize> {
        let n = plaintext.len();
        let u = (n + 1) / 2;
        let v = n - u;

        let mut a = plaintext[..u].to_vec();
        let mut b = plaintext[u..].to_vec();

        for i in 0..8 {
            if i % 2 == 0 {
                let w = self.calculate_w(tweak, i);
                let p = self.calculate_p(i, &w, &b);
                let m = self.radix_power(u);
                let mut rev_a = a.clone();
                rev_a.reverse();
                let a_num = self.digits_to_bigint(&rev_a);
                let y = (&a_num + &p) % &m;
                let mut new = self.bigint_to_digits(&y, u);
                new.reverse();
                a = new;
            } else {
                let w = self.calculate_w(tweak, i);
                let p = self.calculate_p(i, &w, &a);
                let m = self.radix_power(v);
                let mut rev_b = b.clone();
                rev_b.reverse();
                let b_num = self.digits_to_bigint(&rev_b);
                let y = (&b_num + &p) % &m;
                let mut new = self.bigint_to_digits(&y, v);
                new.reverse();
                b = new;
            }
        }

        let mut result = a;
        result.extend(b);
        result
    }

    fn ff3_decrypt(&self, ciphertext: &[usize], tweak: &[u8]) -> Vec<usize> {
        let n = ciphertext.len();
        let u = (n + 1) / 2;
        let v = n - u;

        let mut a = ciphertext[..u].to_vec();
        let mut b = ciphertext[u..].to_vec();

        for i in (0..8).rev() {
            if i % 2 == 0 {
                let w = self.calculate_w(tweak, i);
                let p = self.calculate_p(i, &w, &b);
                let m = self.radix_power(u);
                let mut rev_a = a.clone();
                rev_a.reverse();
                let a_num = self.digits_to_bigint(&rev_a);
                let p_mod = &p % &m;
                let y = (&a_num + &m - &p_mod) % &m;
                let mut new = self.bigint_to_digits(&y, u);
                new.reverse();
                a = new;
            } else {
                let w = self.calculate_w(tweak, i);
                let p = self.calculate_p(i, &w, &a);
                let m = self.radix_power(v);
                let mut rev_b = b.clone();
                rev_b.reverse();
                let b_num = self.digits_to_bigint(&rev_b);
                let p_mod = &p % &m;
                let y = (&b_num + &m - &p_mod) % &m;
                let mut new = self.bigint_to_digits(&y, v);
                new.reverse();
                b = new;
            }
        }

        let mut result = a;
        result.extend(b);
        result
    }

    fn calculate_w(&self, tweak: &[u8], round: usize) -> Vec<u8> {
        let mut w = vec![0u8; 4];
        if round % 2 == 0 {
            w.copy_from_slice(&tweak[4..8]);
        } else {
            w.copy_from_slice(&tweak[..4]);
        }
        w
    }

    fn calculate_p(&self, round: usize, w: &[u8], block: &[usize]) -> BigUint {
        let mut input = [0u8; 16];
        input[..4].copy_from_slice(w);
        input[3] ^= round as u8;

        let mut rev_block = block.to_vec();
        rev_block.reverse();
        let block_num = self.digits_to_bigint(&rev_block);

        let block_bytes = if block_num.is_zero() {
            vec![0u8; 12]
        } else {
            let bytes = block_num.to_bytes_be();
            if bytes.len() <= 12 {
                let mut padded = vec![0u8; 12 - bytes.len()];
                padded.extend(bytes);
                padded
            } else {
                bytes[bytes.len() - 12..].to_vec()
            }
        };

        input[4..].copy_from_slice(&block_bytes);

        let mut reversed_input = input;
        reversed_input.reverse();

        let mut aes_output = Block::from(reversed_input);
        self.aes_cipher.encrypt_block(&mut aes_output);

        let mut output = aes_output.to_vec();
        output.reverse();

        BigUint::from_bytes_be(&output)
    }

    fn digits_to_bigint(&self, digits: &[usize]) -> BigUint {
        let mut result = BigUint::zero();
        let radix = BigUint::from(self.radix);
        for &d in digits {
            result = &result * &radix + BigUint::from(d);
        }
        result
    }

    fn bigint_to_digits(&self, num: &BigUint, length: usize) -> Vec<usize> {
        if num.is_zero() {
            return vec![0; length];
        }
        let mut digits = Vec::new();
        let mut temp = num.clone();
        let radix = BigUint::from(self.radix);
        while !temp.is_zero() {
            let (q, r) = temp.div_rem(&radix);
            let d = r.to_u64_digits();
            digits.push(if d.is_empty() { 0 } else { d[0] as usize });
            temp = q;
        }
        while digits.len() < length {
            digits.push(0);
        }
        digits.reverse();
        digits
    }

    fn radix_power(&self, length: usize) -> BigUint {
        let radix = BigUint::from(self.radix);
        let mut result = BigUint::one();
        for _ in 0..length {
            result *= &radix;
        }
        result
    }

    fn combine_tweaks(&self, additional: &[u8]) -> Vec<u8> {
        let mut combined = self.tweak.clone();
        for (i, &byte) in additional.iter().enumerate() {
            if i < 8 {
                combined[i] ^= byte;
            }
        }
        combined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn radix26() -> Alphabet {
        Alphabet::new("0123456789abcdefghijklmnop").unwrap()
    }

    fn nist_test(key_hex: &str, tweak_hex: &str, radix: usize, plaintext: &str, expected: &str) {
        let key = hex::decode(key_hex).unwrap();
        let tweak = hex::decode(tweak_hex).unwrap();
        let alphabet = match radix {
            10 => cyphera_alphabet::digits(),
            26 => radix26(),
            _ => panic!("unsupported radix in test"),
        };
        let cipher = FF3::new(&key, &tweak, alphabet).unwrap();
        let ct = cipher.encrypt(plaintext).unwrap();
        assert_eq!(ct, expected, "encrypt failed: {plaintext} -> expected {expected}, got {ct}");
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, plaintext, "decrypt roundtrip failed");
    }

    // ── All 15 NIST SP 800-38G FF3 test vectors ────────────────────────

    #[test] fn nist_01() { nist_test("EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73", 10, "890121234567890000", "750918814058654607"); }
    #[test] fn nist_02() { nist_test("EF4359D8D580AA4F7F036D6F04FC6A94", "9A768A92F60E12D8", 10, "890121234567890000", "018989839189395384"); }
    #[test] fn nist_03() { nist_test("EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73", 10, "89012123456789000000789000000", "48598367162252569629397416226"); }
    #[test] fn nist_04() { nist_test("EF4359D8D580AA4F7F036D6F04FC6A94", "0000000000000000", 10, "89012123456789000000789000000", "34695224821734535122613701434"); }
    #[test] fn nist_05() { nist_test("EF4359D8D580AA4F7F036D6F04FC6A94", "9A768A92F60E12D8", 26, "0123456789abcdefghi", "g2pk40i992fn20cjakb"); }
    #[test] fn nist_06() { nist_test("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "D8E7920AFA330A73", 10, "890121234567890000", "646965393875028755"); }
    #[test] fn nist_07() { nist_test("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "9A768A92F60E12D8", 10, "890121234567890000", "961610514491424446"); }
    #[test] fn nist_08() { nist_test("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "D8E7920AFA330A73", 10, "89012123456789000000789000000", "53048884065350204541786380807"); }
    #[test] fn nist_09() { nist_test("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "0000000000000000", 10, "89012123456789000000789000000", "98083802678820389295041483512"); }
    #[test] fn nist_10() { nist_test("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", "9A768A92F60E12D8", 26, "0123456789abcdefghi", "i0ihe2jfj7a9opf9p88"); }
    #[test] fn nist_11() { nist_test("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "D8E7920AFA330A73", 10, "890121234567890000", "922011205562777495"); }
    #[test] fn nist_12() { nist_test("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "9A768A92F60E12D8", 10, "890121234567890000", "504149865578056140"); }
    #[test] fn nist_13() { nist_test("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "D8E7920AFA330A73", 10, "89012123456789000000789000000", "04344343235792599165734622699"); }
    #[test] fn nist_14() { nist_test("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "0000000000000000", 10, "89012123456789000000789000000", "30859239999374053872365555822"); }
    #[test] fn nist_15() { nist_test("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", "9A768A92F60E12D8", 26, "0123456789abcdefghi", "p0b2godfja9bhb7bk38"); }

    // ── General tests ───────────────────────────────────────────────────

    #[test]
    fn test_roundtrip() {
        let key = hex::decode("EF4359D8D580AA4F7F036D6F04FC6A94").unwrap();
        let tweak = hex::decode("D8E7920AFA330A73").unwrap();
        let cipher = FF3::new(&key, &tweak, cyphera_alphabet::digits()).unwrap();
        let ct = cipher.encrypt("1234567890").unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, "1234567890");
        assert_ne!(ct, "1234567890");
    }

    #[test]
    fn test_deterministic() {
        let key = hex::decode("EF4359D8D580AA4F7F036D6F04FC6A94").unwrap();
        let tweak = hex::decode("D8E7920AFA330A73").unwrap();
        let cipher = FF3::new(&key, &tweak, cyphera_alphabet::digits()).unwrap();
        let a = cipher.encrypt("12345").unwrap();
        let b = cipher.encrypt("12345").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_alphanumeric_roundtrip() {
        let key = hex::decode("EF4359D8D580AA4F7F036D6F04FC6A94").unwrap();
        let tweak = hex::decode("D8E7920AFA330A73").unwrap();
        let cipher = FF3::new(&key, &tweak, cyphera_alphabet::alphanumeric_lower()).unwrap();
        let ct = cipher.encrypt("hello123").unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, "hello123");
    }

    #[test]
    fn test_invalid_key() {
        let result = FF3::new(&[0u8; 8], &[0u8; 8], cyphera_alphabet::digits());
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_tweak() {
        let key = hex::decode("EF4359D8D580AA4F7F036D6F04FC6A94").unwrap();
        let result = FF3::new(&key, &[0u8; 4], cyphera_alphabet::digits());
        assert!(result.is_err());
    }
}
