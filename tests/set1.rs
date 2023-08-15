use base64;
use base64::{engine::general_purpose, Engine as _};
use cryptopals::aes128ecb::Aes128Ecb;
use cryptopals::common;

#[test]
fn problem7() -> common::Result<()> {
    let mut reader = common::open(Some("tests/data/7.txt".to_string()))?;
    let mut buf = String::new();
    reader.read_to_string(&mut buf).unwrap();

    let mut ciphertext: Vec<u8> = vec![];

    buf.lines().for_each(|line| {
        let mut ciphertext_block = general_purpose::STANDARD.decode(line).unwrap();
        ciphertext.append(&mut ciphertext_block);
    });

    let mut cipher = Aes128Ecb::from_key("YELLOW SUBMARINE".as_bytes())?;
    let plaintext = cipher.decrypt(&ciphertext)?;
    let answer = include_str!("data/7-plaintext.txt");
    assert_eq!(String::from_utf8(plaintext).unwrap(), answer);

    return Ok(());
}
