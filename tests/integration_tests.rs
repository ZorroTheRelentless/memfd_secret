use memfd_secret::{MemfdSecret, MemfdSecretFlags};
use std::io::{Read, Write};
fn string_sample() -> (MemfdSecret, String) {
    let secret = "le secret";
    let mut vault = MemfdSecret::new(secret.len()).unwrap();
    vault.as_mut_slice().write_all(secret.as_bytes()).unwrap();
    (vault, String::from(secret))
}
#[test]
fn write_retrieve() {
    let (vault, secret) = string_sample();
    let mut read_string = String::new();
    vault.as_slice().read_to_string(&mut read_string).unwrap();
    assert_eq!(read_string, secret);
}

#[test]
fn with_flag_cloexec() {
    let mut vault = MemfdSecret::builder()
        .with_flags(MemfdSecretFlags { cloexec: false })
        .build(1)
        .unwrap();
    vault[0] = 1;
    assert_eq!(vault[0], 1);
}
