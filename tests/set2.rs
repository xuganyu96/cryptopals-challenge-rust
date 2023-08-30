use cryptopals::block;

#[test]
fn problem9() {
    let plaintext = b"YELLOW SUBMARINE";
    let padded = block::pkcs7(plaintext, 20);

    assert_eq!(padded, b"YELLOW SUBMARINE\x04\x04\x04\x04");
}
