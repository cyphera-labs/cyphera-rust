use aes::{Aes128, Aes192, Aes256, Block};
use aes::cipher::{BlockEncrypt, KeyInit};
use num_bigint::BigUint;
use num_traits::Zero;
use num_integer::Integer;
use crate::alphabet::Alphabet;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FF1Error {
    #[error("invalid key length: {0} (expected 16, 24, or 32)")]
    InvalidKeyLength(usize),
    #[error("plaintext too short (min 2 characters)")]
    PlaintextTooShort,
    #[error("plaintext too long (max {0})")]
    PlaintextTooLong(usize),
    #[error("invalid char '{0}' at position {1}")]
    InvalidChar(char, usize),
    #[error("alphabet error: {0}")]
    Alphabet(#[from] crate::alphabet::AlphabetError),
}

/// Trait to abstract over AES key sizes
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

/// FF1 Format-Preserving Encryption cipher (NIST SP 800-38G)
pub struct FF1 {
    radix: usize,
    aes: Box<dyn AesEncryptor>,
    tweak: Vec<u8>,
    max_len: usize,
    alpha: Vec<char>,
    index: HashMap<char, usize>,
}

impl FF1 {
    pub fn new(key: &[u8], tweak: &[u8], alphabet: Alphabet) -> Result<Self, FF1Error> {
        let aes = Self::create_aes(key)?;
        let radix = alphabet.radix();
        let alpha: Vec<char> = alphabet.chars().to_vec();
        let index: HashMap<char, usize> = alpha.iter()
            .enumerate()
            .map(|(i, &c)| (c, i))
            .collect();

        Ok(Self {
            radix,
            aes,
            tweak: tweak.to_vec(),
            max_len: usize::MAX, // NIST FF1 has no max length
            alpha,
            index,
        })
    }

    // NIST SP 800-38G requires AES-ECB as the PRF for FF1/FF3 Feistel rounds.
    // This is single-block encryption used as a building block, not ECB mode applied to user data.
    fn create_aes(key: &[u8]) -> Result<Box<dyn AesEncryptor>, FF1Error> {
        match key.len() {
            16 => Ok(Box::new(Aes128Enc(Aes128::new_from_slice(key).unwrap()))),
            24 => Ok(Box::new(Aes192Enc(Aes192::new_from_slice(key).unwrap()))),
            32 => Ok(Box::new(Aes256Enc(Aes256::new_from_slice(key).unwrap()))),
            n => Err(FF1Error::InvalidKeyLength(n)),
        }
    }

    fn to_digits(&self, s: &str) -> Result<Vec<usize>, FF1Error> {
        s.chars()
            .enumerate()
            .map(|(i, c)| {
                self.index.get(&c)
                    .copied()
                    .ok_or(FF1Error::InvalidChar(c, i))
            })
            .collect()
    }

    fn from_digits(&self, digits: &[usize]) -> String {
        digits.iter().map(|&d| self.alpha[d]).collect()
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String, FF1Error> {
        let digits = self.to_digits(plaintext)?;
        let n = digits.len();
        if n < 2 { return Err(FF1Error::PlaintextTooShort); }
        if n > self.max_len { return Err(FF1Error::PlaintextTooLong(self.max_len)); }
        let result = self.ff1_encrypt(&digits, &self.tweak);
        Ok(self.from_digits(&result))
    }

    pub fn decrypt(&self, ciphertext: &str) -> Result<String, FF1Error> {
        let digits = self.to_digits(ciphertext)?;
        let n = digits.len();
        if n < 2 { return Err(FF1Error::PlaintextTooShort); }
        if n > self.max_len { return Err(FF1Error::PlaintextTooLong(self.max_len)); }
        let result = self.ff1_decrypt(&digits, &self.tweak);
        Ok(self.from_digits(&result))
    }

    pub fn encrypt_with_tweak(&self, plaintext: &str, tweak: &[u8]) -> Result<String, FF1Error> {
        let digits = self.to_digits(plaintext)?;
        let n = digits.len();
        if n < 2 { return Err(FF1Error::PlaintextTooShort); }
        if n > self.max_len { return Err(FF1Error::PlaintextTooLong(self.max_len)); }
        let result = self.ff1_encrypt(&digits, tweak);
        Ok(self.from_digits(&result))
    }

    pub fn decrypt_with_tweak(&self, ciphertext: &str, tweak: &[u8]) -> Result<String, FF1Error> {
        let digits = self.to_digits(ciphertext)?;
        let n = digits.len();
        if n < 2 { return Err(FF1Error::PlaintextTooShort); }
        if n > self.max_len { return Err(FF1Error::PlaintextTooLong(self.max_len)); }
        let result = self.ff1_decrypt(&digits, tweak);
        Ok(self.from_digits(&result))
    }

    // ── NIST SP 800-38G Algorithm 1: FF1.Encrypt ────────────────────────

    fn ff1_encrypt(&self, plaintext: &[usize], tweak: &[u8]) -> Vec<usize> {
        let n = plaintext.len();
        let radix = self.radix;
        let u = n / 2;
        let v = n - u;

        let mut a: Vec<usize> = plaintext[..u].to_vec();
        let mut b: Vec<usize> = plaintext[u..].to_vec();

        let b_bytes = self.compute_b(v);
        let d = 4 * ((b_bytes + 3) / 4) + 4;
        let p = self.build_p(radix, u, n, tweak.len());

        for i in 0..10 {
            let num_b = self.digits_to_bigint(&b);
            let num_b_bytes = self.bigint_to_bytes(&num_b, b_bytes);
            let q = self.build_q(tweak, i, &num_b_bytes, b_bytes);

            let mut pq = p.clone();
            pq.extend_from_slice(&q);

            let r = self.prf(&pq);
            let s = self.expand_s(&r, d);
            let y = BigUint::from_bytes_be(&s);

            let m = if i % 2 == 0 { u } else { v };

            let num_a = self.digits_to_bigint(&a);
            let c = (num_a + y) % self.radix_power(m);
            let c_digits = self.bigint_to_digits(&c, m);

            a = b;
            b = c_digits;
        }

        let mut result = a;
        result.extend(b);
        result
    }

    // ── NIST SP 800-38G Algorithm 2: FF1.Decrypt ────────────────────────

    fn ff1_decrypt(&self, ciphertext: &[usize], tweak: &[u8]) -> Vec<usize> {
        let n = ciphertext.len();
        let radix = self.radix;
        let u = n / 2;
        let v = n - u;

        let mut a: Vec<usize> = ciphertext[..u].to_vec();
        let mut b: Vec<usize> = ciphertext[u..].to_vec();

        let b_bytes = self.compute_b(v);
        let d = 4 * ((b_bytes + 3) / 4) + 4;
        let p = self.build_p(radix, u, n, tweak.len());

        for i in (0..10).rev() {
            let num_a = self.digits_to_bigint(&a);
            let num_a_bytes = self.bigint_to_bytes(&num_a, b_bytes);
            let q = self.build_q(tweak, i, &num_a_bytes, b_bytes);

            let mut pq = p.clone();
            pq.extend_from_slice(&q);

            let r = self.prf(&pq);
            let s = self.expand_s(&r, d);
            let y = BigUint::from_bytes_be(&s);

            let m = if i % 2 == 0 { u } else { v };

            let modulus = self.radix_power(m);
            let num_b = self.digits_to_bigint(&b);

            // Modular subtraction: (num_b - y) mod modulus
            let y_mod = &y % &modulus;
            let c = if num_b >= y_mod {
                (&num_b - &y_mod) % &modulus
            } else {
                (&num_b + &modulus - &y_mod) % &modulus
            };
            let c_digits = self.bigint_to_digits(&c, m);

            b = a;
            a = c_digits;
        }

        let mut result = a;
        result.extend(b);
        result
    }

    // ── Helper functions per NIST spec ──────────────────────────────────

    /// Compute b = ceil(ceil(v * log2(radix)) / 8)
    fn compute_b(&self, v: usize) -> usize {
        let radix_big = BigUint::from(self.radix);
        let mut pow = BigUint::from(1u32);
        for _ in 0..v {
            pow *= &radix_big;
        }
        pow -= BigUint::from(1u32);
        let bits = if pow.is_zero() { 1 } else { pow.bits() as usize };
        (bits + 7) / 8
    }

    /// Build P block (16 bytes) per step 3
    fn build_p(&self, radix: usize, u: usize, n: usize, t: usize) -> Vec<u8> {
        let mut p = Vec::with_capacity(16);
        p.push(1);
        p.push(2);
        p.push(1);
        p.push((radix >> 16) as u8);
        p.push((radix >> 8) as u8);
        p.push(radix as u8);
        p.push(10);
        p.push(u as u8);
        p.extend_from_slice(&(n as u32).to_be_bytes());
        p.extend_from_slice(&(t as u32).to_be_bytes());
        p
    }

    /// Build Q block per step 5
    fn build_q(&self, tweak: &[u8], i: usize, num_bytes: &[u8], b: usize) -> Vec<u8> {
        let t = tweak.len();
        let pad = (16 - ((t + 1 + b) % 16)) % 16;
        let mut q = Vec::with_capacity(t + pad + 1 + b);
        q.extend_from_slice(tweak);
        q.extend(std::iter::repeat(0u8).take(pad));
        q.push(i as u8);
        // Pad num_bytes to b length
        if num_bytes.len() < b {
            q.extend(std::iter::repeat(0u8).take(b - num_bytes.len()));
        }
        let start = if num_bytes.len() > b { num_bytes.len() - b } else { 0 };
        q.extend_from_slice(&num_bytes[start..]);
        q
    }

    /// PRF: AES-CBC-MAC over data (must be multiple of 16 bytes)
    fn prf(&self, data: &[u8]) -> [u8; 16] {
        let mut y = [0u8; 16];
        for chunk in data.chunks(16) {
            let mut tmp = [0u8; 16];
            for j in 0..16 {
                tmp[j] = y[j] ^ chunk[j];
            }
            let mut block = Block::from(tmp);
            self.aes.encrypt_block(&mut block);
            y.copy_from_slice(&block);
        }
        y
    }

    /// Expand R to d bytes per NIST SP 800-38G: S = R || AES(R ⊕ [1]) || AES(R ⊕ [2]) || ...
    fn expand_s(&self, r: &[u8; 16], d: usize) -> Vec<u8> {
        let need_blocks = (d + 15) / 16;
        let mut out = Vec::with_capacity(need_blocks * 16);
        out.extend_from_slice(r);
        for j in 1..need_blocks {
            let mut x = [0u8; 16];
            x[8..16].copy_from_slice(&(j as u64).to_be_bytes());
            // XOR with R (not previous block) per NIST SP 800-38G
            for k in 0..16 {
                x[k] ^= r[k];
            }
            let mut block = Block::from(x);
            self.aes.encrypt_block(&mut block);
            let arr: [u8; 16] = block.into();
            out.extend_from_slice(&arr);
        }
        out.truncate(d);
        out
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

    fn bigint_to_bytes(&self, x: &BigUint, b: usize) -> Vec<u8> {
        let bytes = x.to_bytes_be();
        if bytes.len() >= b {
            bytes[bytes.len() - b..].to_vec()
        } else {
            let mut result = vec![0u8; b - bytes.len()];
            result.extend_from_slice(&bytes);
            result
        }
    }

    fn radix_power(&self, length: usize) -> BigUint {
        let radix = BigUint::from(self.radix);
        let mut result = BigUint::from(1u32);
        for _ in 0..length {
            result *= &radix;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NIST SP 800-38G FF1 test vectors
    // Sample 1: AES-128, radix 10
    #[test]
    fn test_nist_sample_1() {
        let key = hex::decode("2B7E151628AED2A6ABF7158809CF4F3C").unwrap();
        let tweak = hex::decode("").unwrap();
        let cipher = FF1::new(&key, &tweak, crate::alphabet::digits()).unwrap();
        let ct = cipher.encrypt("0123456789").unwrap();
        assert_eq!(ct, "2433477484");
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, "0123456789");
    }

    // Sample 2: AES-128, radix 10, with tweak
    #[test]
    fn test_nist_sample_2() {
        let key = hex::decode("2B7E151628AED2A6ABF7158809CF4F3C").unwrap();
        let tweak = hex::decode("39383736353433323130").unwrap();
        let cipher = FF1::new(&key, &tweak, crate::alphabet::digits()).unwrap();
        let ct = cipher.encrypt("0123456789").unwrap();
        assert_eq!(ct, "6124200773");
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, "0123456789");
    }

    // Sample 3: AES-128, radix 36
    #[test]
    fn test_nist_sample_3() {
        let key = hex::decode("2B7E151628AED2A6ABF7158809CF4F3C").unwrap();
        let tweak = hex::decode("3737373770717273373737").unwrap();
        let cipher = FF1::new(&key, &tweak, crate::alphabet::alphanumeric_lower()).unwrap();
        let ct = cipher.encrypt("0123456789abcdefghi").unwrap();
        assert_eq!(ct, "a9tv40mll9kdu509eum");
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, "0123456789abcdefghi");
    }

    // Sample 4: AES-192, radix 10
    #[test]
    fn test_nist_sample_4() {
        let key = hex::decode("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F").unwrap();
        let tweak = hex::decode("").unwrap();
        let cipher = FF1::new(&key, &tweak, crate::alphabet::digits()).unwrap();
        let ct = cipher.encrypt("0123456789").unwrap();
        assert_eq!(ct, "2830668132");
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, "0123456789");
    }

    // Sample 5: AES-192, radix 10, with tweak
    #[test]
    fn test_nist_sample_5() {
        let key = hex::decode("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F").unwrap();
        let tweak = hex::decode("39383736353433323130").unwrap();
        let cipher = FF1::new(&key, &tweak, crate::alphabet::digits()).unwrap();
        let ct = cipher.encrypt("0123456789").unwrap();
        assert_eq!(ct, "2496655549");
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, "0123456789");
    }

    // Sample 6: AES-192, radix 36
    #[test]
    fn test_nist_sample_6() {
        let key = hex::decode("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F").unwrap();
        let tweak = hex::decode("3737373770717273373737").unwrap();
        let cipher = FF1::new(&key, &tweak, crate::alphabet::alphanumeric_lower()).unwrap();
        let ct = cipher.encrypt("0123456789abcdefghi").unwrap();
        assert_eq!(ct, "xbj3kv35jrawxv32ysr");
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, "0123456789abcdefghi");
    }

    // Sample 7: AES-256, radix 10
    #[test]
    fn test_nist_sample_7() {
        let key = hex::decode("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94").unwrap();
        let tweak = hex::decode("").unwrap();
        let cipher = FF1::new(&key, &tweak, crate::alphabet::digits()).unwrap();
        let ct = cipher.encrypt("0123456789").unwrap();
        assert_eq!(ct, "6657667009");
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, "0123456789");
    }

    // Sample 8: AES-256, radix 10, with tweak
    #[test]
    fn test_nist_sample_8() {
        let key = hex::decode("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94").unwrap();
        let tweak = hex::decode("39383736353433323130").unwrap();
        let cipher = FF1::new(&key, &tweak, crate::alphabet::digits()).unwrap();
        let ct = cipher.encrypt("0123456789").unwrap();
        assert_eq!(ct, "1001623463");
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, "0123456789");
    }

    // Sample 9: AES-256, radix 36
    #[test]
    fn test_nist_sample_9() {
        let key = hex::decode("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94").unwrap();
        let tweak = hex::decode("3737373770717273373737").unwrap();
        let cipher = FF1::new(&key, &tweak, crate::alphabet::alphanumeric_lower()).unwrap();
        let ct = cipher.encrypt("0123456789abcdefghi").unwrap();
        assert_eq!(ct, "xs8a0azh2avyalyzuwd");
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, "0123456789abcdefghi");
    }

    #[test]
    fn test_roundtrip() {
        let key = vec![0u8; 16];
        let tweak = vec![];
        let cipher = FF1::new(&key, &tweak, crate::alphabet::digits()).unwrap();
        let ct = cipher.encrypt("1234567890").unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, "1234567890");
        assert_ne!(ct, "1234567890");
    }

    #[test]
    fn test_deterministic() {
        let key = vec![0u8; 16];
        let tweak = vec![];
        let cipher = FF1::new(&key, &tweak, crate::alphabet::digits()).unwrap();
        let a = cipher.encrypt("12345").unwrap();
        let b = cipher.encrypt("12345").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_alphanumeric_roundtrip() {
        let key = vec![0u8; 32];
        let tweak = vec![];
        let cipher = FF1::new(&key, &tweak, crate::alphabet::alphanumeric_lower()).unwrap();
        let ct = cipher.encrypt("hello123world").unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, "hello123world");
    }
}
