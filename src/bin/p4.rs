//! https://cryptopals.com/sets/1/challenges/4
use clap::Parser;
use cryptopals::caesar::{self, EnglishFrequency};
use hex;
use std::fs;

/// One of the 60-character strings in the input file has been encrypted by single-byte XOR, find
/// it.
#[derive(Debug, Parser)]
struct Args {
    /// List the N best decryptions. Defaults to 5
    #[arg(short)]
    #[arg(default_value_t = 5)]
    n: usize,

    /// Print not only the best decryption, but also its corresponding ciphertext (with hex
    /// encoding) and decryption key
    #[arg(long)]
    verbose: bool,

    /// The input data file
    file: String,
}

/// Try every key for every ciphertext, each time recording the MSE with the reference frequencies.
/// List the N best
fn main() {
    let args = Args::parse();
    println!("{:?}", args);

    let _inputs = fs::read_to_string(args.file)
        .unwrap()
        .lines()
        .enumerate()
        .filter_map(|(i, line)| match hex::decode(line.to_string()) {
            Ok(bytes) => Some((i, bytes)),
            Err(_) => None,
        })
        .for_each(|(i, ciphertext)| {
            // TODO: for now this is enough to uncover the plaintext; add some additional logic to
            // rank decryptions across plaintexts so that the best one is ranked at the top.
            let best_keys =
                caesar::n_best_keys(&ciphertext, &EnglishFrequency::reference(), args.n, false);
            for key in best_keys {
                let pt = caesar::decrypt(&ciphertext, &key);
                let mse = EnglishFrequency::from_bytes(&pt)
                    .unwrap()
                    .mse(&EnglishFrequency::reference());
                let pt_str = String::from_utf8(pt);
                if pt_str.is_ok() {
                    println!("line: {i}, key: {key}, mse: {mse}, plaintext: {pt_str:?}");
                }
            }
        });
}
