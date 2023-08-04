//! https://cryptopals.com/sets/1/challenges/5
//! Repeating key XOR.
//!
//! Note that in ths prompt of the challenge, both the input and the key are UTF-8 text, so in this
//! implementation they will be UTF-8 text.
//!
//! To run this exercise against the sample input:
//!
//! echo -n "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
//! | cargo run --bin p5 -- --key "ICE"
//!
//! The output should be:
//! 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c65
//! 2a3124333a653e2b2027630c692b20283165286326302e27282f
use clap::Parser;
use cryptopals::vigenere::{self, RepeatingKey};
use hex;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read};

#[derive(Debug, Parser)]
struct Args {
    /// The key is UTF-8 text
    #[arg(long)]
    key: String,

    /// The input data as a file path; if empty, read from stdin.
    /// The input data is assumed to be UTF-8 text and will be encrypted line by line
    data: Option<String>,
}

/// Open a file if there is a path, else open stdin
fn open(path: Option<String>) -> Result<Box<dyn Read>, Box<dyn Error>> {
    return match path {
        None => Ok(Box::new(io::stdin())),
        Some(file_path) => {
            let file = File::open(file_path)?;
            Ok(Box::new(file))
        }
    };
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let mut reader = open(args.data)?;
    let mut plaintext: String = String::new();
    reader.read_to_string(&mut plaintext)?;
    let ciphertext = vigenere::encrypt(
        &plaintext.as_bytes(),
        RepeatingKey::new(&args.key.as_bytes()),
    );
    println!("{}", hex::encode(ciphertext));

    return Ok(());
}
