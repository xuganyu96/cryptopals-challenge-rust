//! https://cryptopals.com/sets/1/challenges/4
use clap::Parser;
use cryptopals::caesar::{self, EnglishFrequency};
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

    /// Print not only the best decryption, but also its corresponding ciphertext (with hex
    /// encoding) and decryption key
    #[arg(long)]
    verbose: bool,

    /// The input data file
    file: String,
}

fn main() {
    let args = Args::parse();

    let mut global_best_decryptions = fs::read_to_string(args.file)
        .unwrap()
        .lines()
        .enumerate()
        .filter_map(|(i, line)| match hex::decode(line.to_string()) {
            Ok(ciphertext) => Some((i, ciphertext)),
            Err(_) => None,
        })
        .map(|(i, ciphertext)| {
            // map each ciphertext to a vector of its best decryptions
            let best_keys =
                caesar::n_best_keys(&ciphertext, &EnglishFrequency::reference(), 0, true);
            return best_keys
                .iter()
                .map(|key| (i, ciphertext.clone(), *key))
                .collect::<Vec<(usize, Vec<u8>, u8)>>();
        })
        .flatten() // from vector of vectors to just the elements
        .map(|(i, ciphertext, key)| {
            let pt = caesar::decrypt(&ciphertext, &key);
            let mse = EnglishFrequency::from_bytes(&pt)
                .unwrap()
                .mse(&EnglishFrequency::reference());
            return (i, ciphertext, key, pt, mse);
        })
        .collect::<Vec<(usize, Vec<u8>, u8, Vec<u8>, f64)>>();
    global_best_decryptions.sort_by(|elem1, elem2| {
        let (_, _, _, _, mse1) = elem1;
        let (_, _, _, _, mse2) = elem2;
        return mse1.partial_cmp(mse2).unwrap();
    });
    global_best_decryptions.into_iter().take(args.n).for_each(
        |(i, ciphertext, key, plaintext, mse)| {
            println!("line: {i}, key: {key}, score: {mse}");
            println!("    ciphertext: {}", hex::encode(ciphertext));
            println!("    plaintext: {:?}", String::from_utf8(plaintext));
        },
    );
}
