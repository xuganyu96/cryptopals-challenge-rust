use cryptopals::encoding;
use cryptopals::vigenere;
use std::collections::HashMap;

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
fn problem7() {
    use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
    use aes::Aes128;

    let blocksize: usize = 16;
    let ciphertext_str = include_str!("./data/7.txt");
    let answer_str = include_str!("./data/7-plaintext.txt");
    let ciphertext: Vec<u8> = ciphertext_str
        .lines()
        .map(|line| encoding::decode_base64(line).unwrap())
        .flatten()
        .collect();
    let mut plaintext: Vec<u8> = vec![];

    // build the cipher
    let cipher = Aes128::new_from_slice(b"YELLOW SUBMARINE").unwrap();

    // Decrypt the ciphertext block by block
    let nblocks = ciphertext.len() / blocksize;
    for i in 0..nblocks {
        let mut block: [u8; 16] = [0u8; 16];
        let block_start = i * blocksize;
        let block_end = (i + 1) * blocksize;
        block.copy_from_slice(&ciphertext[block_start..block_end]);
        let mut block = GenericArray::from(block);
        cipher.decrypt_block(&mut block);
        let plaintext_block = block.to_vec();

        // Remove padding from the plaintext block if it is the last block
        if i == (nblocks - 1) {
            let pad = plaintext_block.get(plaintext_block.len() - 1).unwrap();
            let pad: usize = (*pad) as usize; // the last "pad" number of bytes are pad
            let end = plaintext_block.len() - pad;
            plaintext.extend_from_slice(plaintext_block.get(0..end).unwrap());
        } else {
            plaintext.extend_from_slice(&plaintext_block);
        }
    }
    assert_eq!(String::from_utf8(plaintext).unwrap(), answer_str,);
}

/// https://cryptopals.com/sets/1/challenges/8
/// One of the hex-encoded ciphertexts is encoded with AES in ECB mode, detect it.
#[test]
fn problem8() {
    let ciphertexts = include_str!("data/8.txt");

    let ciphertexts_scores = ciphertexts
        .lines()
        .enumerate()
        .filter_map(|(i, ciphertext_hex)| {
            let ciphertext = hex::decode(ciphertext_hex).unwrap();
            let blocksize: usize = 16;

            // Count the number of repeating blocks
            let mut counts = HashMap::new();
            let mut j = 0;
            while (j + 1) * blocksize <= ciphertext.len() {
                let block_start = j * blocksize;
                let block_end = (j + 1) * blocksize;
                let block = ciphertext.get(block_start..block_end).unwrap().to_vec();
                let count = counts.get(&block).unwrap_or(&0);
                counts.insert(block, count + 1);
                j += 1;
            }

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
}
