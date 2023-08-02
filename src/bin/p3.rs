//! https://cryptopals.com/sets/1/challenges/3
use hex;

const INPUTS: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

fn decrypt(ciphertext: &[u8], key: &u8) -> Vec<u8> {
    return ciphertext.iter()
        .map(|byte| byte ^ key)
        .collect::<Vec<u8>>();
}

/// True if the byte can encode a printable ASCII character
fn is_ascii(byte: &u8) -> bool {
    return (32u8..127u8).contains(byte);
}

// TODO: implement frequency analysis

fn main() {
    let inputs = hex::decode(INPUTS).unwrap();
    // TODO: implement frequency analysis
    for key in 0u8..=255u8 {
        let plaintext = decrypt(&inputs, &key);

        let all_ascii = plaintext.iter()
            .all(|byte| is_ascii(byte));

        let outputs = String::from_utf8(plaintext);
        if outputs.is_ok() && all_ascii {
            println!("{outputs:?}");
        }
    }
}
