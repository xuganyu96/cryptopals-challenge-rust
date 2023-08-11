//! https://cryptopals.com/sets/1/challenges/6
use base64;
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use cryptopals::caesar::EnglishFrequency;
use cryptopals::common;
use cryptopals::vigenere;
use std::error::Error;

/// The input data has been encrypted with repeating-key XOR and encoded in base-64. This program
/// tries to solve it. Example:
///
/// cargo run --bin p6 -- inputs/6.txt
#[derive(Debug, Parser)]
struct Args {
    /// Try only the top n decryptions; defaults to 10
    #[arg(short)]
    #[arg(default_value_t = 10)]
    n: usize,

    /// Path to the file containing the input data. If not file path is given, read from stdin
    data: Option<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let mut reader = common::open(args.data)?;
    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;

    let ciphertext_b64: String = buf
        .lines()
        .map(|line| line.to_string())
        .collect::<Vec<String>>()
        .join("");
    let ciphertext = general_purpose::STANDARD.decode(ciphertext_b64)?;
    let keysizes = vigenere::rank_keysizes(&ciphertext);
    keysizes.iter().take(args.n).for_each(|(keysize, hamming)| {
        println!("key: {:?}, hamming: {:?}", keysize, hamming);
        let key =
            vigenere::solve_with_keysize(&ciphertext, *keysize, &EnglishFrequency::reference());
        let plaintext = vigenere::decrypt(&ciphertext, &key);
        println!("{:?}", String::from_utf8(plaintext));
    });

    return Ok(());
}
