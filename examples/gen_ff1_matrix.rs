//! Generates the adversarial FF1 b-calculation conformance matrix.
//!
//! Emits a cyphera-conformance engine fixture: many (radix, length) pairs,
//! each exercising a distinct FF1 `b = ceil(ceil(v*log2(radix))/8)`. Run from
//! the verified, floating-point-free cyphera-rust FF1 engine — the `expected`
//! values are the ground truth every other SDK must reproduce. A b-calculation
//! bug in any SDK yields a divergent ciphertext that the conformance run flags.
//!
//!   cargo run --example gen_ff1_matrix > ff1_b_matrix.json

use cyphera::ff1::core::FF1;
use cyphera::alphabet::Alphabet;

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    let key_hex = "2B7E151628AED2A6ABF7158809CF4F3C";
    let tweak_hex = "39383736353433323130";
    let key = hex_decode(key_hex);
    let tweak = hex_decode(tweak_hex);

    // (alphabet, minimum NIST-domain length for that radix)
    let radixes: &[(&str, usize)] = &[
        ("01", 20),
        ("01234567", 7),
        ("0123456789", 6),
        ("0123456789abcdef", 5),
        ("0123456789abcdefghijklmnopqrstuv", 4),
        ("abcdefghijklmnopqrstuvwxyz", 5),
        ("0123456789abcdefghijklmnopqrstuvwxyz", 4),
        ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 4),
        ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/", 4),
    ];
    // Length offsets above each radix's minimum — chosen so v = ceil(n/2)
    // walks a wide range of values across the matrix.
    let offsets = [0usize, 1, 2, 3, 4, 6, 9, 13, 18, 24, 31];

    let mut cases: Vec<String> = Vec::new();
    for (alpha_str, min_len) in radixes {
        let alpha_chars: Vec<char> = alpha_str.chars().collect();
        let r = alpha_chars.len();
        for off in offsets {
            let len = min_len + off;
            let pt: String = (0..len).map(|i| alpha_chars[(i * 7 + 3) % r]).collect();
            let cipher = FF1::new(&key, &tweak, Alphabet::new(alpha_str).unwrap()).unwrap();
            let ct = cipher.encrypt(&pt).unwrap();
            cases.push(format!(
                "    {{ \"key\": \"{}\", \"tweak\": \"{}\", \"alphabet\": \"{}\", \"plaintext\": \"{}\", \"expected\": \"{}\" }}",
                key_hex, tweak_hex, alpha_str, pt, ct
            ));
        }
    }

    println!("{{");
    println!("  \"engine\": \"ff1\",");
    println!("  \"source\": \"Adversarial FF1 b-calculation matrix — generated from the verified cyphera-rust FF1 engine\",");
    println!("  \"note\": \"Radix x length matrix stressing the FF1 b-parameter ceil(ceil(v*log2(radix))/8) across many (radix, v) pairs. An implementation that computes b with floating-point log2 (the Bouncy-Castle-class bug NIST forbids) diverges on some of these cases. Every SDK must reproduce expected exactly.\",");
    println!("  \"cases\": [");
    println!("{}", cases.join(",\n"));
    println!("  ]");
    println!("}}");
}
