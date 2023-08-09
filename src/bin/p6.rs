//! https://cryptopals.com/sets/1/challenges/6
use clap::Parser;
use cryptopals::common;
use std::error::Error;

/// The input data has been encrypted with repeating-key XOR and encoded in base-64. This program
/// tries to solve it. Example:
///
/// cargo run --bin p6 -- inputs/6.txt
#[derive(Debug, Parser)]
struct Args {
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
    println!("{}", ciphertext_b64);

    return Ok(());
}
