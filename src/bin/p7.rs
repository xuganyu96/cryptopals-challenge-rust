use std::error::Error;
use base64;
use base64::{engine::general_purpose, Engine as _};
use cryptopals::common;
use cryptopals::aes128ecb::Aes128Ecb;


fn main() -> Result<(), Box<dyn Error>> {
    let mut reader = common::open(Some("inputs/7.txt".to_string()))?;
    let mut buf = String::new();
    reader.read_to_string(&mut buf).unwrap();

    let mut ciphertext: Vec<u8> = vec![];

    buf.lines()
        .for_each(|line| {
            let mut ciphertext_block = general_purpose::STANDARD.decode(line).unwrap();
            ciphertext.append(&mut ciphertext_block);
        });

    let mut cipher = Aes128Ecb::from_key("YELLOW SUBMARINE".as_bytes())?;
    let plaintext = cipher.decrypt(&ciphertext)?;
    println!("{}", String::from_utf8(plaintext).unwrap());

    return Ok(());
}
