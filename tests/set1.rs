use base64;
use base64::{engine::general_purpose, Engine as _};
use cryptopals::aes128ecb::Aes128Ecb;
use cryptopals::common;
use cryptopals::encoding;

#[test]
fn problem1() {
    let hex_str: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let base64_str: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let bytes = encoding::decode_hex(hex_str).unwrap();
    assert_eq!(encoding::encode_base64(&bytes), base64_str);
}

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

/// https://cryptopals.com/sets/1/challenges/8
/// One of the hex-encoded ciphertexts is encoded with AES in ECB mode, detect it.
#[test]
fn problem8() -> common::Result<()> {
    let ciphertexts = include_str!("data/8.txt");

    let ciphertexts_scores = ciphertexts
        .lines()
        .enumerate()
        .filter_map(|(i, ciphertext_hex)| {
            let ciphertext = hex::decode(ciphertext_hex).unwrap();
            let counts = common::count_block_frequency(&ciphertext, 16).unwrap();

            // We score by counting the number of repeated blocks, in other words, sum of all
            // values minus the number of keys
            let total: usize = counts.values().sum();
            let nkeys: usize = counts.keys().count();

            if (total - nkeys) != 0 {
                return Some((i, total - nkeys));
            }
            return None;
        })
        .collect::<Vec<(usize, usize)>>();
    assert_eq!(ciphertexts_scores.len(), 1);

    return Ok(());
}
