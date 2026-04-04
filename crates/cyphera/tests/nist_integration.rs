//! NIST test vectors running through the full Cyphera SDK.
//!
//! Proves the entire stack works: policy file → key resolution → engine dispatch
//! → correct NIST output → decrypt roundtrip.

use cyphera::{Client, KeychainProvider};
use cyphera::keys::{MemoryProvider, KeyRecord, KeyStatus};
use cyphera::policy::PolicyFile;
use keychain::{KeyStore, KeyConfig};
use keychain_env::EnvBackend;
use std::collections::HashMap;

// ── FF1 NIST vectors through SDK ────────────────────────────────────────

fn ff1_policy_and_provider() -> (PolicyFile, Box<KeychainProvider>) {
    let yaml = r#"
policies:
  ff1-128-digits:
    engine: ff1
    alphabet: digits
    key_ref: ff1-128
  ff1-128-digits-tweaked:
    engine: ff1
    alphabet: digits
    key_ref: ff1-128-tweaked
  ff1-128-base36:
    engine: ff1
    alphabet: alphanumeric
    key_ref: ff1-128-base36
  ff1-192-digits:
    engine: ff1
    alphabet: digits
    key_ref: ff1-192
  ff1-192-digits-tweaked:
    engine: ff1
    alphabet: digits
    key_ref: ff1-192-tweaked
  ff1-192-base36:
    engine: ff1
    alphabet: alphanumeric
    key_ref: ff1-192-base36
  ff1-256-digits:
    engine: ff1
    alphabet: digits
    key_ref: ff1-256
  ff1-256-digits-tweaked:
    engine: ff1
    alphabet: digits
    key_ref: ff1-256-tweaked
  ff1-256-base36:
    engine: ff1
    alphabet: alphanumeric
    key_ref: ff1-256-base36
"#;
    let pf = PolicyFile::from_yaml(yaml).unwrap();

    let key128 = hex::decode("2B7E151628AED2A6ABF7158809CF4F3C").unwrap();
    let key192 = hex::decode("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F").unwrap();
    let key256 = hex::decode("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94").unwrap();
    let tweak_empty = vec![];
    let tweak_9 = hex::decode("39383736353433323130").unwrap();
    let tweak_77 = hex::decode("3737373770717273373737").unwrap();

    let store = KeyStore::new()
        .register(Box::new(EnvBackend::new()))
        .key("ff1-128", KeyConfig {
            uri: "env://NIST_FF1_128".into(),
            tweak: Some(tweak_empty.clone()),
            algorithm: None, version: None, metadata: HashMap::new(),
        })
        .key("ff1-128-tweaked", KeyConfig {
            uri: "env://NIST_FF1_128".into(),
            tweak: Some(tweak_9.clone()),
            algorithm: None, version: None, metadata: HashMap::new(),
        })
        .key("ff1-128-base36", KeyConfig {
            uri: "env://NIST_FF1_128".into(),
            tweak: Some(tweak_77.clone()),
            algorithm: None, version: None, metadata: HashMap::new(),
        })
        .key("ff1-192", KeyConfig {
            uri: "env://NIST_FF1_192".into(),
            tweak: Some(tweak_empty.clone()),
            algorithm: None, version: None, metadata: HashMap::new(),
        })
        .key("ff1-192-tweaked", KeyConfig {
            uri: "env://NIST_FF1_192".into(),
            tweak: Some(tweak_9.clone()),
            algorithm: None, version: None, metadata: HashMap::new(),
        })
        .key("ff1-192-base36", KeyConfig {
            uri: "env://NIST_FF1_192".into(),
            tweak: Some(tweak_77.clone()),
            algorithm: None, version: None, metadata: HashMap::new(),
        })
        .key("ff1-256", KeyConfig {
            uri: "env://NIST_FF1_256".into(),
            tweak: Some(tweak_empty),
            algorithm: None, version: None, metadata: HashMap::new(),
        })
        .key("ff1-256-tweaked", KeyConfig {
            uri: "env://NIST_FF1_256".into(),
            tweak: Some(tweak_9),
            algorithm: None, version: None, metadata: HashMap::new(),
        })
        .key("ff1-256-base36", KeyConfig {
            uri: "env://NIST_FF1_256".into(),
            tweak: Some(tweak_77),
            algorithm: None, version: None, metadata: HashMap::new(),
        });

    // Set env vars with raw key bytes
    std::env::set_var("NIST_FF1_128", unsafe { String::from_utf8_unchecked(key128) });
    std::env::set_var("NIST_FF1_192", unsafe { String::from_utf8_unchecked(key192) });
    std::env::set_var("NIST_FF1_256", unsafe { String::from_utf8_unchecked(key256) });

    let provider = KeychainProvider::new(store, vec![]);
    (pf, Box::new(provider))
}

// Env backend with raw bytes is tricky for non-UTF8 keys.
// Let's use MemoryProvider directly for NIST vectors — cleaner.

fn ff1_client() -> Client {
    let yaml = r#"
policies:
  s1: { engine: ff1, alphabet: digits, key_ref: k128 }
  s2: { engine: ff1, alphabet: digits, key_ref: k128-t9 }
  s3: { engine: ff1, alphabet: alphanumeric, key_ref: k128-t77 }
  s4: { engine: ff1, alphabet: digits, key_ref: k192 }
  s5: { engine: ff1, alphabet: digits, key_ref: k192-t9 }
  s6: { engine: ff1, alphabet: alphanumeric, key_ref: k192-t77 }
  s7: { engine: ff1, alphabet: digits, key_ref: k256 }
  s8: { engine: ff1, alphabet: digits, key_ref: k256-t9 }
  s9: { engine: ff1, alphabet: alphanumeric, key_ref: k256-t77 }
"#;
    let pf = PolicyFile::from_yaml(yaml).unwrap();

    let key128 = hex::decode("2B7E151628AED2A6ABF7158809CF4F3C").unwrap();
    let key192 = hex::decode("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F").unwrap();
    let key256 = hex::decode("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94").unwrap();
    let t_empty: Vec<u8> = vec![];
    let t_9 = hex::decode("39383736353433323130").unwrap();
    let t_77 = hex::decode("3737373770717273373737").unwrap();

    let provider = MemoryProvider::new(vec![
        KeyRecord { key_ref: "k128".into(), version: 1, status: KeyStatus::Active, material: key128.clone(), tweak: t_empty.clone() },
        KeyRecord { key_ref: "k128-t9".into(), version: 1, status: KeyStatus::Active, material: key128.clone(), tweak: t_9.clone() },
        KeyRecord { key_ref: "k128-t77".into(), version: 1, status: KeyStatus::Active, material: key128, tweak: t_77.clone() },
        KeyRecord { key_ref: "k192".into(), version: 1, status: KeyStatus::Active, material: key192.clone(), tweak: t_empty.clone() },
        KeyRecord { key_ref: "k192-t9".into(), version: 1, status: KeyStatus::Active, material: key192.clone(), tweak: t_9.clone() },
        KeyRecord { key_ref: "k192-t77".into(), version: 1, status: KeyStatus::Active, material: key192, tweak: t_77.clone() },
        KeyRecord { key_ref: "k256".into(), version: 1, status: KeyStatus::Active, material: key256.clone(), tweak: t_empty },
        KeyRecord { key_ref: "k256-t9".into(), version: 1, status: KeyStatus::Active, material: key256.clone(), tweak: t_9 },
        KeyRecord { key_ref: "k256-t77".into(), version: 1, status: KeyStatus::Active, material: key256, tweak: t_77 },
    ]);

    Client::from_policy(pf, Box::new(provider))
}

fn ff3_client() -> Client {
    let yaml = r#"
policies:
  s1:  { engine: ff3, alphabet: digits, key_ref: k128-t1 }
  s2:  { engine: ff3, alphabet: digits, key_ref: k128-t2 }
  s3:  { engine: ff3, alphabet: digits, key_ref: k128-t1-long }
  s4:  { engine: ff3, alphabet: digits, key_ref: k128-t0-long }
  s6:  { engine: ff3, alphabet: digits, key_ref: k192-t1 }
  s7:  { engine: ff3, alphabet: digits, key_ref: k192-t2 }
  s8:  { engine: ff3, alphabet: digits, key_ref: k192-t1-long }
  s9:  { engine: ff3, alphabet: digits, key_ref: k192-t0-long }
  s11: { engine: ff3, alphabet: digits, key_ref: k256-t1 }
  s12: { engine: ff3, alphabet: digits, key_ref: k256-t2 }
  s13: { engine: ff3, alphabet: digits, key_ref: k256-t1-long }
  s14: { engine: ff3, alphabet: digits, key_ref: k256-t0-long }
"#;
    let pf = PolicyFile::from_yaml(yaml).unwrap();

    let key128 = hex::decode("EF4359D8D580AA4F7F036D6F04FC6A94").unwrap();
    let key192 = hex::decode("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6").unwrap();
    let key256 = hex::decode("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C").unwrap();
    let t1 = hex::decode("D8E7920AFA330A73").unwrap();
    let t2 = hex::decode("9A768A92F60E12D8").unwrap();
    let t0 = hex::decode("0000000000000000").unwrap();

    let provider = MemoryProvider::new(vec![
        KeyRecord { key_ref: "k128-t1".into(), version: 1, status: KeyStatus::Active, material: key128.clone(), tweak: t1.clone() },
        KeyRecord { key_ref: "k128-t2".into(), version: 1, status: KeyStatus::Active, material: key128.clone(), tweak: t2.clone() },
        KeyRecord { key_ref: "k128-t1-long".into(), version: 1, status: KeyStatus::Active, material: key128.clone(), tweak: t1.clone() },
        KeyRecord { key_ref: "k128-t0-long".into(), version: 1, status: KeyStatus::Active, material: key128, tweak: t0.clone() },
        KeyRecord { key_ref: "k192-t1".into(), version: 1, status: KeyStatus::Active, material: key192.clone(), tweak: t1.clone() },
        KeyRecord { key_ref: "k192-t2".into(), version: 1, status: KeyStatus::Active, material: key192.clone(), tweak: t2.clone() },
        KeyRecord { key_ref: "k192-t1-long".into(), version: 1, status: KeyStatus::Active, material: key192.clone(), tweak: t1.clone() },
        KeyRecord { key_ref: "k192-t0-long".into(), version: 1, status: KeyStatus::Active, material: key192, tweak: t0.clone() },
        KeyRecord { key_ref: "k256-t1".into(), version: 1, status: KeyStatus::Active, material: key256.clone(), tweak: t1.clone() },
        KeyRecord { key_ref: "k256-t2".into(), version: 1, status: KeyStatus::Active, material: key256.clone(), tweak: t2 },
        KeyRecord { key_ref: "k256-t1-long".into(), version: 1, status: KeyStatus::Active, material: key256.clone(), tweak: t1 },
        KeyRecord { key_ref: "k256-t0-long".into(), version: 1, status: KeyStatus::Active, material: key256, tweak: t0 },
    ]);

    Client::from_policy(pf, Box::new(provider))
}

// ── FF1 NIST Samples via SDK ────────────────────────────────────────────

#[test] fn ff1_nist_s1() { let c = ff1_client(); assert_sdk(&c, "s1", "0123456789", "2433477484"); }
#[test] fn ff1_nist_s2() { let c = ff1_client(); assert_sdk(&c, "s2", "0123456789", "6124200773"); }
#[test] fn ff1_nist_s3() { let c = ff1_client(); assert_sdk(&c, "s3", "0123456789abcdefghi", "a9tv40mll9kdu509eum"); }
#[test] fn ff1_nist_s4() { let c = ff1_client(); assert_sdk(&c, "s4", "0123456789", "2830668132"); }
#[test] fn ff1_nist_s5() { let c = ff1_client(); assert_sdk(&c, "s5", "0123456789", "2496655549"); }
#[test] fn ff1_nist_s6() { let c = ff1_client(); assert_sdk(&c, "s6", "0123456789abcdefghi", "xbj3kv35jrawxv32ysr"); }
#[test] fn ff1_nist_s7() { let c = ff1_client(); assert_sdk(&c, "s7", "0123456789", "6657667009"); }
#[test] fn ff1_nist_s8() { let c = ff1_client(); assert_sdk(&c, "s8", "0123456789", "1001623463"); }
#[test] fn ff1_nist_s9() { let c = ff1_client(); assert_sdk(&c, "s9", "0123456789abcdefghi", "xs8a0azh2avyalyzuwd"); }

// ── FF3 NIST Samples via SDK ────────────────────────────────────────────

#[test] fn ff3_nist_s1()  { let c = ff3_client(); assert_sdk(&c, "s1",  "890121234567890000", "750918814058654607"); }
#[test] fn ff3_nist_s2()  { let c = ff3_client(); assert_sdk(&c, "s2",  "890121234567890000", "018989839189395384"); }
#[test] fn ff3_nist_s3()  { let c = ff3_client(); assert_sdk(&c, "s3",  "89012123456789000000789000000", "48598367162252569629397416226"); }
#[test] fn ff3_nist_s4()  { let c = ff3_client(); assert_sdk(&c, "s4",  "89012123456789000000789000000", "34695224821734535122613701434"); }
#[test] fn ff3_nist_s6()  { let c = ff3_client(); assert_sdk(&c, "s6",  "890121234567890000", "646965393875028755"); }
#[test] fn ff3_nist_s7()  { let c = ff3_client(); assert_sdk(&c, "s7",  "890121234567890000", "961610514491424446"); }
#[test] fn ff3_nist_s8()  { let c = ff3_client(); assert_sdk(&c, "s8",  "89012123456789000000789000000", "53048884065350204541786380807"); }
#[test] fn ff3_nist_s9()  { let c = ff3_client(); assert_sdk(&c, "s9",  "89012123456789000000789000000", "98083802678820389295041483512"); }
#[test] fn ff3_nist_s11() { let c = ff3_client(); assert_sdk(&c, "s11", "890121234567890000", "922011205562777495"); }
#[test] fn ff3_nist_s12() { let c = ff3_client(); assert_sdk(&c, "s12", "890121234567890000", "504149865578056140"); }
#[test] fn ff3_nist_s13() { let c = ff3_client(); assert_sdk(&c, "s13", "89012123456789000000789000000", "04344343235792599165734622699"); }
#[test] fn ff3_nist_s14() { let c = ff3_client(); assert_sdk(&c, "s14", "89012123456789000000789000000", "30859239999374053872365555822"); }

// ── Helper ──────────────────────────────────────────────────────────────

fn assert_sdk(client: &Client, policy: &str, plaintext: &str, expected_ct: &str) {
    // Encrypt via SDK
    let ct = client.encrypt(policy, plaintext)
        .unwrap_or_else(|e| panic!("encrypt({policy}, {plaintext}) failed: {e}"));
    assert_eq!(ct.output, expected_ct,
        "NIST vector mismatch for policy '{policy}': encrypt('{plaintext}') = '{}', expected '{expected_ct}'",
        ct.output);

    // Decrypt roundtrip
    let pt = client.decrypt(policy, &ct.output)
        .unwrap_or_else(|e| panic!("decrypt({policy}, {}) failed: {e}", ct.output));
    assert_eq!(pt.output, plaintext,
        "Roundtrip failed for policy '{policy}': decrypt('{}') = '{}', expected '{plaintext}'",
        ct.output, pt.output);
}
