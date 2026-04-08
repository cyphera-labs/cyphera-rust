//! NIST test vectors running through the full Cyphera SDK.
//!
//! Proves the entire stack works: policy file -> key resolution -> engine dispatch
//! -> correct NIST output -> decrypt roundtrip.

use cyphera::Client;
use cyphera::keys::{MemoryProvider, KeyRecord, KeyStatus};
use cyphera::policy::PolicyFile;

fn ff1_client() -> Client {
    let yaml = r#"
policies:
  s1: { engine: ff1, alphabet: digits, key_ref: k128, tag_enabled: false }
  s2: { engine: ff1, alphabet: digits, key_ref: k128-t9, tag_enabled: false }
  s3: { engine: ff1, alphabet: "0123456789abcdefghijklmnopqrstuvwxyz", key_ref: k128-t77, tag_enabled: false }
  s4: { engine: ff1, alphabet: digits, key_ref: k192, tag_enabled: false }
  s5: { engine: ff1, alphabet: digits, key_ref: k192-t9, tag_enabled: false }
  s6: { engine: ff1, alphabet: "0123456789abcdefghijklmnopqrstuvwxyz", key_ref: k192-t77, tag_enabled: false }
  s7: { engine: ff1, alphabet: digits, key_ref: k256, tag_enabled: false }
  s8: { engine: ff1, alphabet: digits, key_ref: k256-t9, tag_enabled: false }
  s9: { engine: ff1, alphabet: "0123456789abcdefghijklmnopqrstuvwxyz", key_ref: k256-t77, tag_enabled: false }
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

    Client::from_policy(pf, Box::new(provider)).unwrap()
}

fn ff3_client() -> Client {
    let yaml = r#"
policies:
  s1:  { engine: ff3, alphabet: digits, key_ref: k128-t1, tag_enabled: false }
  s2:  { engine: ff3, alphabet: digits, key_ref: k128-t2, tag_enabled: false }
  s3:  { engine: ff3, alphabet: digits, key_ref: k128-t1-long, tag_enabled: false }
  s4:  { engine: ff3, alphabet: digits, key_ref: k128-t0-long, tag_enabled: false }
  s6:  { engine: ff3, alphabet: digits, key_ref: k192-t1, tag_enabled: false }
  s7:  { engine: ff3, alphabet: digits, key_ref: k192-t2, tag_enabled: false }
  s8:  { engine: ff3, alphabet: digits, key_ref: k192-t1-long, tag_enabled: false }
  s9:  { engine: ff3, alphabet: digits, key_ref: k192-t0-long, tag_enabled: false }
  s11: { engine: ff3, alphabet: digits, key_ref: k256-t1, tag_enabled: false }
  s12: { engine: ff3, alphabet: digits, key_ref: k256-t2, tag_enabled: false }
  s13: { engine: ff3, alphabet: digits, key_ref: k256-t1-long, tag_enabled: false }
  s14: { engine: ff3, alphabet: digits, key_ref: k256-t0-long, tag_enabled: false }
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

    Client::from_policy(pf, Box::new(provider)).unwrap()
}

// -- FF1 NIST Samples via SDK --

#[test] fn ff1_nist_s1() { let c = ff1_client(); assert_sdk(&c, "s1", "0123456789", "2433477484"); }
#[test] fn ff1_nist_s2() { let c = ff1_client(); assert_sdk(&c, "s2", "0123456789", "6124200773"); }
#[test] fn ff1_nist_s3() { let c = ff1_client(); assert_sdk(&c, "s3", "0123456789abcdefghi", "a9tv40mll9kdu509eum"); }
#[test] fn ff1_nist_s4() { let c = ff1_client(); assert_sdk(&c, "s4", "0123456789", "2830668132"); }
#[test] fn ff1_nist_s5() { let c = ff1_client(); assert_sdk(&c, "s5", "0123456789", "2496655549"); }
#[test] fn ff1_nist_s6() { let c = ff1_client(); assert_sdk(&c, "s6", "0123456789abcdefghi", "xbj3kv35jrawxv32ysr"); }
#[test] fn ff1_nist_s7() { let c = ff1_client(); assert_sdk(&c, "s7", "0123456789", "6657667009"); }
#[test] fn ff1_nist_s8() { let c = ff1_client(); assert_sdk(&c, "s8", "0123456789", "1001623463"); }
#[test] fn ff1_nist_s9() { let c = ff1_client(); assert_sdk(&c, "s9", "0123456789abcdefghi", "xs8a0azh2avyalyzuwd"); }

// -- FF3 NIST Samples via SDK --

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

// -- Helper --

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
