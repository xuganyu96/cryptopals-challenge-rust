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

    let keys = vigenere::solve_caesar(&ciphertext);
    let (key, _) = keys.get(0).unwrap();
    let plaintext = vigenere::decrypt(&ciphertext, &[*key]);
    let plaintext_str = String::from_utf8(plaintext).unwrap();
    assert_eq!(plaintext_str, "Cooking MC's like a pound of bacon");
}

/// Break Fixed-length XOR, part 2
///
/// Similar to problem 3, but with 60 lines of ciphertexts among which one of them is encrypted
/// with a Caesar cipher. There are some arbitary filtering, but in the end the thing works so I
/// will move on
#[test]
fn problem4() {
    let mut decryptions: Vec<(usize, u8, f64)> = vec![]; // line_no, key, mse
    let ciphertext_str = include_str!("data/4.txt");
    let ciphertexts = ciphertext_str
        .lines()
        .map(|line| hex::decode(line).unwrap())
        .collect::<Vec<Vec<u8>>>();

    ciphertexts.iter().enumerate().for_each(|(i, ciphertext)| {
        let keys = vigenere::solve_caesar(&ciphertext);
        for (key, mse) in keys {
            decryptions.push((i, key, mse));
        }
    });

    decryptions.sort_by(|elem1, elem2| {
        let (_, _, mse1) = elem1;
        let (_, _, mse2) = elem2;
        return mse1.partial_cmp(mse2).unwrap();
    });

    let (i, key, _) = decryptions.get(0).unwrap();
    let ciphertext = ciphertexts.get(*i).unwrap();
    let plaintext = vigenere::decrypt(ciphertext, &[*key]);
    let plaintext_str = String::from_utf8(plaintext).unwrap();
    assert_eq!(plaintext_str, "Now that the party is jumping\n");
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
