//! Test messages from the RIPEMD-160 webpage[1]
//! [1] https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
//!
#[macro_use]
extern crate hex_literal;
extern crate ripemd128;
use ripemd128::{Digest, Ripemd128};

fn hash_test(msg: &str, expected: [u8; 16]) {
    let mut hasher = Ripemd128::new();
    hasher.input(msg.as_bytes());
    let result = hasher.result();
    assert_eq!(result[..], expected);
}

#[test]
fn ripemd128_messages() {
    hash_test("", hex!("cdf26213a150dc3ecb610f18f6b38b46"));
    hash_test("a", hex!("86be7afa339d0fc7cfc785e72f578d33"));
    hash_test("abc", hex!("c14a12199c66e4ba84636b0f69144c77"));
    hash_test("message digest", hex!("9e327b3d6e523062afc1132d7df9d1b8"));
    hash_test(
        "abcdefghijklmnopqrstuvwxyz",
        hex!("fd2aa607f71dc8f510714922b371834e"),
    );
    hash_test(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        hex!("a1aa0689d0fafa2ddc22e88b49133a06"),
    );
    hash_test(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        hex!("d1e959eb179c911faea4624c60c5c702"),
    );
    hash_test(
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        hex!("3f45ef194732c2dbb2c4a2c769795fa3"),
    );
}

#[test]
fn ripemd128_1million_a() {
    let v = vec!['a' as u8; 1_000_000];

    let mut hasher = Ripemd128::new();
    hasher.input(&v[..]);
    let result = hasher.result();
    assert_eq!(result[..], hex!("4a7f5723f954eba1216c9d8f6320431f"));
}
