//! https://cryptopals.com/sets/1/challenges/4
use std::fs;
use clap::Parser;

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


    let _inputs = fs::read_to_string(args.file).unwrap();
}
