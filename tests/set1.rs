use base64;
use base64::{engine::general_purpose, Engine as _};
use cryptopals::aes128ecb::Aes128Ecb;
use cryptopals::common;
use cryptopals::encoding;
use cryptopals::vigenere;

/// Convert the hex encoding to base64 encoding
#[test]
fn problem1() {
    let hex_str: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let base64_str: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let bytes = encoding::decode_hex(hex_str).unwrap();
    assert_eq!(encoding::encode_base64(&bytes), base64_str);
}

/// Fixed-length XOR
/// While we could approach by writing a dedicated function for doing fixed-length XOR, knowing
/// that in later problems there will be implementations of Caesar and Vigenere ciphers, it's
/// easier to implement a Vigenere cipher and just use that
#[test]
fn problem2() {
    let plaintext_str: &str = "1c0111001f010100061a024b53535009181c";
    let key_str: &str = "686974207468652062756c6c277320657965";

    let plaintext = encoding::decode_hex(plaintext_str).unwrap();
    let key = encoding::decode_hex(key_str).unwrap();
    let ciphertext = vigenere::encrypt(&plaintext, &key);

    assert_eq!(
        encoding::encode_hex(&ciphertext),
        "746865206b696420646f6e277420706c6179"
    );
}

/// Break Fixed-length XOR
///
/// Again, this is implemented with the foresight that we will be doing Vigenere later, and that
/// Caesar cipher is just Vigenere cipher with a key length of 1
#[test]
fn problem3() {
    let ciphertext_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let ciphertext = hex::decode(ciphertext_hex).unwrap();

    let key = vigenere::solve_with_keysize(&ciphertext, 1).unwrap();
    let plaintext = vigenere::decrypt(&ciphertext, &key);
    let plaintext_str = String::from_utf8(plaintext).unwrap();
    assert_eq!(plaintext_str, "Cooking MC's like a pound of bacon");
}

/// Break Fixed-length XOR, part 2
///
/// For each line, produce the best decryption, then find the best
#[test]
fn problem4() {
    let ciphertext_str = include_str!("data/4.txt");
    let plaintext_strs: Vec<String> = ciphertext_str
        .lines()
        .filter_map(|line| {
            let ciphertext = hex::decode(line).unwrap();
            let key = vigenere::solve_with_keysize(&ciphertext, 1);
            let plaintext = match key {
                Some(key) => vigenere::decrypt(&ciphertext, &key),
                None => return None,
            };
            return match String::from_utf8(plaintext) {
                Ok(plaintext_str) => Some(plaintext_str),
                Err(_) => None,
            };
        })
        .collect();
    // there could be multiple accepted decryptions. We only need to make sure that the correct
    // decryption is among them
    assert!(plaintext_strs
        .iter()
        .any(|plaintext_str| plaintext_str == "Now that the party is jumping\n"));
}

/// Implement repeating-key XOR
#[test]
fn problem5() {
    let plaintext = concat!(
        "Burning 'em, if you ain't quick and nimble\n",
        "I go crazy when I hear a cymbal"
    );
    let key = b"ICE";
    let ciphertext = vigenere::encrypt(plaintext.as_bytes(), key);

    assert_eq!(
        hex::encode(ciphertext),
        concat!(
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b",
            "2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        )
    );
}

/// Break repeating-key XOR
#[test]
fn problem6() {
    let ciphertext_str = include_str!("data/6.txt");
    let correct_keysize = 29;
    let answer_str = include_str!("../tests/data/6-plaintext.txt");

    let ciphertext: Vec<u8> = ciphertext_str
        .lines()
        .map(|line| encoding::decode_base64(line).unwrap())
        .flatten()
        .collect::<Vec<u8>>();
    let keysizes = vigenere::find_keysizes(&ciphertext);
    // Normally the solving process takes a few moments, but in this case I already know the
    // answer, so the correct keysize is picked to speed up testing
    assert!(keysizes.contains(&correct_keysize));
    let key = vigenere::solve_with_keysize(&ciphertext, correct_keysize).unwrap();
    let plaintext = vigenere::decrypt(&ciphertext, &key);
    let plaintext_str = String::from_utf8(plaintext).unwrap();
    assert_eq!(plaintext_str, answer_str);
}

#[test]
fn problem7() -> common::Result<()> {
    let mut ciphertext: Vec<u8> = vec![];

    include_str!("data/7.txt").lines().for_each(|line| {
        let mut ciphertext_block = general_purpose::STANDARD.decode(line).unwrap();
        ciphertext.append(&mut ciphertext_block);
    });

    let mut cipher = Aes128Ecb::from_key("YELLOW SUBMARINE".as_bytes())?;
    let plaintext = cipher.decrypt(&ciphertext)?;
    assert_eq!(
        String::from_utf8(plaintext).unwrap(),
        include_str!("data/7-plaintext.txt")
    );

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
