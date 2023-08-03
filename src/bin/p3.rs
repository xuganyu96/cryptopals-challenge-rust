//! https://cryptopals.com/sets/1/challenges/3
//!
//! To run the Caesar cipher decrypter, use the following command:
//! p3 "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
use clap::Parser;
use cryptopals::caesar::{self, EnglishFrequency};
use hex;
use std::error::Error;

/// The hex-encoded input string is the ciphertext of some single-byte XOR cipher. Find the key and
/// decrypt the message
#[derive(Debug, Parser)]
struct Args {
    /// Return the N best decryptions; defaults to 3
    #[arg(short)]
    #[arg(default_value_t = 3)]
    n: usize,

    /// The input bytes, encoded in hexadecimal numbers
    input_str: String,
}

/// ASCII test alone is enough to delimiate possible keys to human scale
fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let ciphertext = hex::decode(args.input_str)?;

    let best_keys = caesar::n_best_keys(&ciphertext, &EnglishFrequency::reference(), args.n);
    best_keys.iter().enumerate().for_each(|(i, key)| {
        let plaintext = caesar::decrypt(&ciphertext, key);
        let mse = EnglishFrequency::from_bytes(&plaintext)
            .unwrap()
            .mse(&EnglishFrequency::reference());
        let plaintext_str = String::from_utf8(plaintext);
        println!("rank: {i}, key: {key}, MSE: {mse}\nmessage: {plaintext_str:?}");
    });

    return Ok(());
}
