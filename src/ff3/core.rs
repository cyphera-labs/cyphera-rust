use aes::{Aes128, Aes192, Aes256, Block};
use aes::cipher::{BlockEncrypt, KeyInit};
use num_bigint::BigUint;
use num_traits::{Zero, One};
use num_integer::Integer;
use crate::alphabet::Alphabet;
use std::collections::HashMap;

#[derive(Debug)]
pub enum FF3Error {
    InvalidKeyLength(usize),
    InvalidTweakLength { got: usize, expected: usize },
    PlaintextTooShort,
    PlaintextTooLong,
    InvalidChar(char, usize),
    AlphabetError(crate::alphabet::AlphabetError),
}

impl std::fmt::Display for FF3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyLength(n) => write!(f, "invalid key length: {n} (expected 16, 24, or 32)"),
            Self::InvalidTweakLength { got, expected } => write!(f, "invalid tweak length: {got} (expected {expected})"),
            Self::PlaintextTooShort => write!(f, "input too short (NIST minimum: length >= 2 and radix^length >= 1,000,000)"),
            Self::PlaintextTooLong => write!(f, "plaintext too long"),
            Self::InvalidChar(c, pos) => write!(f, "invalid char '{c}' at position {pos}"),
            Self::AlphabetError(e) => write!(f, "alphabet error: {e}"),
        }
    }
}

impl std::error::Error for FF3Error {}

impl From<crate::alphabet::AlphabetError> for FF3Error {
    fn from(e: crate::alphabet::AlphabetError) -> Self {
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

/// FF3 (NIST SP 800-38G) Format-Preserving Encryption cipher.
///
/// This is the **original** FF3, which is cryptographically weak and
/// deprecated. New code should use [`FF31`] (FF3-1, SP 800-38G Rev 1).
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
            return Err(FF3Error::InvalidTweakLength { got: tweak.len(), expected: 8 });
        }

        let radix = alphabet.radix();
        let aes_cipher = Self::create_aes(key)?;
        // NIST SP 800-38G: maxlen = 2 * floor(96 / log2(radix)).
        // (radix 10 -> 56, radix 26 -> 40, radix 62/64 -> 32)
        let max_len = 2 * ((96.0 / (radix as f64).log2()).floor() as usize);

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

    // NIST SP 800-38G requires AES-ECB as the PRF for FF1/FF3 Feistel rounds.
    // This is single-block encryption used as a building block, not ECB mode applied to user data.
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

    #[allow(clippy::wrong_self_convention)]
    fn from_digits(&self, digits: &[usize]) -> String {
        digits.iter().map(|&d| self.alpha[d]).collect()
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String, FF3Error> {
        let digits = self.to_digits(plaintext)?;
        let n = digits.len();
        self.check_length(n)?;
        let result = self.ff3_encrypt(&digits, &self.tweak);
        Ok(self.from_digits(&result))
    }

    pub fn decrypt(&self, ciphertext: &str) -> Result<String, FF3Error> {
        let digits = self.to_digits(ciphertext)?;
        let n = digits.len();
        self.check_length(n)?;
        let result = self.ff3_decrypt(&digits, &self.tweak);
        Ok(self.from_digits(&result))
    }

    pub fn encrypt_with_tweak(&self, plaintext: &str, additional_tweak: &[u8]) -> Result<String, FF3Error> {
        let digits = self.to_digits(plaintext)?;
        let n = digits.len();
        self.check_length(n)?;
        let tweak = self.combine_tweaks(additional_tweak);
        let result = self.ff3_encrypt(&digits, &tweak);
        Ok(self.from_digits(&result))
    }

    pub fn decrypt_with_tweak(&self, ciphertext: &str, additional_tweak: &[u8]) -> Result<String, FF3Error> {
        let digits = self.to_digits(ciphertext)?;
        let n = digits.len();
        self.check_length(n)?;
        let tweak = self.combine_tweaks(additional_tweak);
        let result = self.ff3_decrypt(&digits, &tweak);
        Ok(self.from_digits(&result))
    }

    // ── Core FF3 algorithm ──────────────────────────────────────────────

    fn ff3_encrypt(&self, plaintext: &[usize], tweak: &[u8]) -> Vec<usize> {
        let n = plaintext.len();
        let u = n.div_ceil(2);
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
        let u = n.div_ceil(2);
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

    /// NIST SP 800-38G minimum-domain check: length >= 2 and
    /// radix^length >= 1,000,000.
    fn check_length(&self, n: usize) -> Result<(), FF3Error> {
        if n < self.min_len || self.radix_power(n) < BigUint::from(1_000_000u32) {
            return Err(FF3Error::PlaintextTooShort);
        }
        if n > self.max_len {
            return Err(FF3Error::PlaintextTooLong);
        }
        Ok(())
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

/// FF3-1 (NIST SP 800-38G Revision 1) Format-Preserving Encryption.
///
/// FF3-1 is FF3 with a 56-bit (7-byte) tweak. The 56-bit tweak is expanded
/// into the 64-bit form the FF3 round function consumes; everything downstream
/// is identical FF3. FF3-1 supersedes the original FF3, which is
/// cryptographically weak.
pub struct FF31 {
    inner: FF3,
}

impl FF31 {
    /// Create an FF3-1 cipher. `tweak` MUST be exactly 7 bytes (56 bits).
    pub fn new(key: &[u8], tweak: &[u8], alphabet: Alphabet) -> Result<Self, FF3Error> {
        if tweak.len() != 7 {
            return Err(FF3Error::InvalidTweakLength { got: tweak.len(), expected: 7 });
        }
        let expanded = Self::expand_tweak(tweak);
        Ok(Self { inner: FF3::new(key, &expanded, alphabet)? })
    }

    /// Expand the 56-bit FF3-1 tweak into the 64-bit tweak FF3 consumes.
    ///
    /// Per NIST SP 800-38G Rev 1, with `expanded[0..4]` = T_L and
    /// `expanded[4..8]` = T_R:
    ///   T_L = T[0..27] ‖ 0000
    ///   T_R = T[32..55] ‖ T[28..31] ‖ 0000
    fn expand_tweak(t: &[u8]) -> [u8; 8] {
        [
            t[0], t[1], t[2], t[3] & 0xF0,
            t[4], t[5], t[6], (t[3] & 0x0F) << 4,
        ]
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String, FF3Error> {
        self.inner.encrypt(plaintext)
    }

    pub fn decrypt(&self, ciphertext: &str) -> Result<String, FF3Error> {
        self.inner.decrypt(ciphertext)
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
            10 => crate::alphabet::digits(),
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

    // ── FF3-1: all 18 NIST ACVP AES-FF3-1 test vectors ─────────────────

    fn ff31_test(key_hex: &str, tweak_hex: &str, alpha: &str, plaintext: &str, expected: &str) {
        let key = hex::decode(key_hex).unwrap();
        let tweak = hex::decode(tweak_hex).unwrap();
        let alphabet = Alphabet::new(alpha).unwrap();
        let cipher = FF31::new(&key, &tweak, alphabet).unwrap();
        let ct = cipher.encrypt(plaintext).unwrap();
        assert_eq!(ct, expected, "FF3-1 encrypt: {plaintext} -> expected {expected}, got {ct}");
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, plaintext, "FF3-1 decrypt roundtrip failed");
    }

    const A26: &str = "abcdefghijklmnopqrstuvwxyz";
    const A64: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

    #[test] fn acvp_ff31_01() { ff31_test("2DE79D232DF5585D68CE47882AE256D6", "CBD09280979564", "0123456789", "3992520240", "8901801106"); }
    #[test] fn acvp_ff31_02() { ff31_test("01C63017111438F7FC8E24EB16C71AB5", "C4E822DCD09F27", "0123456789", "60761757463116869318437658042297305934914824457484538562", "35637144092473838892796702739628394376915177448290847293"); }
    #[test] fn acvp_ff31_03() { ff31_test("718385E6542534604419E83CE387A437", "B6F35084FA90E1", A26, "wfmwlrorcd", "ywowehycyd"); }
    #[test] fn acvp_ff31_04() { ff31_test("DB602DFF22ED7E84C8D8C865A941A238", "EBEFD63BCC2083", A26, "kkuomenbzqvggfbteqdyanwpmhzdmoicekiihkrm", "belcfahcwwytwrckieymthabgjjfkxtxauipmjja"); }
    #[test] fn acvp_ff31_05() { ff31_test("AEE87D0D485B3AFD12BD1E0B9D03D50D", "5F9140601D224B", A64, "ixvuuIHr0e", "GR90R1q838"); }
    #[test] fn acvp_ff31_06() { ff31_test("7B6C88324732F7F4AD435DA9AD77F917", "3F42102C0BAB39", A64, "21q1kbbIVSrAFtdFWzdMeIDpRqpo", "cvQ/4aGUV4wRnyO3CHmgEKW5hk8H"); }
    #[test] fn acvp_ff31_07() { ff31_test("F62EDB777A671075D47563F3A1E9AC797AA706A2D8E02FC8", "493B8451BF6716", "0123456789", "4406616808", "1807744762"); }
    #[test] fn acvp_ff31_08() { ff31_test("0951B475D1A327C52756F2624AF224C80E9BE85F09B2D44F", "D679E2EA3054E1", "0123456789", "99980459818278359406199791971849884432821321826358606310", "84359031857952748660483617398396641079558152339419110919"); }
    #[test] fn acvp_ff31_09() { ff31_test("49CCB8F62D941E5684599ECA0300937B5C766D053E109777", "0BFCF75CDC2FC1", A26, "jaxlrchjjx", "kjdbfqyahd"); }
    #[test] fn acvp_ff31_10() { ff31_test("03D253674A9309FF07ED0E71B24CBFE769025E09FCE544D7", "B33176B1DA0F6C", A26, "tafzrybuvhiqvcyztuxfnwfprmqlwpayphxbawpl", "loaemzbgqkywkdhmncrijzildzleoqibtthdiliv"); }
    #[test] fn acvp_ff31_11() { ff31_test("1C24B74B7C1B9969314CB53E92F98EFD620D5520017FB076", "0380341C425A6F", A64, "6np8r2t8zo", "HgpCXoA1Rt"); }
    #[test] fn acvp_ff31_12() { ff31_test("C0ABADFC071379824A070E8C3FD40DD9BFD7A3C99A0D5FE3", "6C2926C705DDAF", A64, "GKB6sa9g56BSJ09iJ4dsaxRdsMvo", "gC0tTSdDPxM79QOWi+z+SNL9C4V+"); }
    #[test] fn acvp_ff31_13() { ff31_test("1FAA03EFF55A06F8FAB3F1DC57127D493E2F8F5C365540467A3A055BDBE6481D", "4D67130C030445", "0123456789", "3679409436", "1735794859"); }
    #[test] fn acvp_ff31_14() { ff31_test("9CE16E125BD422A011408EB083355E7089E70A4CD2F59E141D0B94A74BCC5967", "4684635BD2C821", "0123456789", "85783290820098255530464619643265070052870796363685134012", "75104723514036464144839960480545848044718729603261409917"); }
    #[test] fn acvp_ff31_15() { ff31_test("6187F8BDE99F7DAF9E3EE8A8654308E7E51D31FA88AFFAEB5592041C033B736B", "5820812B3D5DD1", A26, "mkblaoiyfd", "ifpyiihvvq"); }
    #[test] fn acvp_ff31_16() { ff31_test("F6807FB9688937E4D4956006C8F0CB2394148A5F4B14666CF353F4941428FFD7", "30C87B99890096", A26, "wrammvhudopmaazlsxevzwzwpezzmghwfnmkitnk", "nzftnfkliuctlmtdfrxfhwgevrbcbgljurnytxkj"); }
    #[test] fn acvp_ff31_17() { ff31_test("9C2B69F7DDF181C54398E345BE04C2F6B00B9DD1679200E1E04C4FF961AE0F09", "103C238B4B1E44", A64, "H2/c6FblSA", "EOg4H1bE+8"); }
    #[test] fn acvp_ff31_18() { ff31_test("C58BCBD08B90006CEC7E82B2D987D79F6A21111DEF0CEBB273CBAEB2D6CD4044", "7036604882667B", A64, "bz5TcS1krnD8IOLdrQeKzXkLAa6h", "Z6x3/9LPW8SZunRezRM8J68Q4J03"); }

    #[test]
    fn ff31_rejects_8_byte_tweak() {
        let key = hex::decode("2DE79D232DF5585D68CE47882AE256D6").unwrap();
        let r = FF31::new(&key, &[0u8; 8], crate::alphabet::digits());
        assert!(r.is_err());
    }

    #[test]
    fn rejects_below_nist_domain() {
        // NIST SP 800-38G: radix^len must be >= 1,000,000.
        // 5 digits, radix 10 -> 10^5 = 100,000 < 1,000,000 -> reject.
        let key = hex::decode("EF4359D8D580AA4F7F036D6F04FC6A94").unwrap();
        let tweak = hex::decode("D8E7920AFA330A73").unwrap();
        let cipher = FF3::new(&key, &tweak, crate::alphabet::digits()).unwrap();
        assert!(cipher.encrypt("12345").is_err());
        assert!(cipher.encrypt("123456").is_ok()); // 10^6 = exactly 1,000,000
    }

    // ── General tests ───────────────────────────────────────────────────

    #[test]
    fn test_roundtrip() {
        let key = hex::decode("EF4359D8D580AA4F7F036D6F04FC6A94").unwrap();
        let tweak = hex::decode("D8E7920AFA330A73").unwrap();
        let cipher = FF3::new(&key, &tweak, crate::alphabet::digits()).unwrap();
        let ct = cipher.encrypt("1234567890").unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, "1234567890");
        assert_ne!(ct, "1234567890");
    }

    #[test]
    fn test_deterministic() {
        let key = hex::decode("EF4359D8D580AA4F7F036D6F04FC6A94").unwrap();
        let tweak = hex::decode("D8E7920AFA330A73").unwrap();
        let cipher = FF3::new(&key, &tweak, crate::alphabet::digits()).unwrap();
        let a = cipher.encrypt("123456").unwrap();
        let b = cipher.encrypt("123456").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_alphanumeric_roundtrip() {
        let key = hex::decode("EF4359D8D580AA4F7F036D6F04FC6A94").unwrap();
        let tweak = hex::decode("D8E7920AFA330A73").unwrap();
        let cipher = FF3::new(&key, &tweak, crate::alphabet::alphanumeric_lower()).unwrap();
        let ct = cipher.encrypt("hello123").unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, "hello123");
    }

    #[test]
    fn test_invalid_key() {
        let result = FF3::new(&[0u8; 8], &[0u8; 8], crate::alphabet::digits());
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_tweak() {
        let key = hex::decode("EF4359D8D580AA4F7F036D6F04FC6A94").unwrap();
        let result = FF3::new(&key, &[0u8; 4], crate::alphabet::digits());
        assert!(result.is_err());
    }
}
