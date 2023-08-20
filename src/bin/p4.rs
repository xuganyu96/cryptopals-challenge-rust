//! https://cryptopals.com/sets/1/challenges/4
use clap::Parser;
use cryptopals::vigenere;
use hex;
use std::fs;

/// One of the 60-character strings in the input file has been encrypted by single-byte XOR, find
/// it.
#[derive(Debug, Parser)]
struct Args {
    /// List the N best decryptions. Defaults to 3
    #[arg(short)]
    #[arg(default_value_t = 3)]
    n: usize,

    /// The input data file
    file: String,
}

fn main() {
    let args = Args::parse();

    let mut decryptions: Vec<(usize, u8, f64)> = vec![]; // line_no, key, mse
    let ciphertexts = fs::read_to_string(args.file)
        .unwrap()
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
    decryptions.iter().take(5).for_each(|(i, key, mse)| {
        let ciphertext = ciphertexts.get(*i).unwrap();
        let plaintext = vigenere::decrypt(ciphertext, &[*key]);
        let plaintext_str = String::from_utf8(plaintext);
        println!("line: {i}, key: {key}, mse: {mse}");
        println!("  ciphertext: {ciphertext:?}");
        println!("  plaintext: {plaintext_str:?}");
    });
}
