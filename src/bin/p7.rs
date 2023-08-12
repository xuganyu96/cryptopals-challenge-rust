//! https://cryptopals.com/sets/1/challenges/7
use base64;
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use cryptopals::aes::Aes128Ecb;
use cryptopals::common;
use std::error::Error;

/// Decrypt the input data file (ciphertext encoded with base-64) using AES-128 in ECB mode
#[derive(Debug, Parser)]
struct Args {
    /// The encryption key. If no encryption key is specified, the input text is assumed to be
    /// unencrypted
    #[arg(long)]
    passphrase: Option<String>,

    /// Path to the data file
    data: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let mut buf = String::new();
    let mut reader = common::open(Some(args.data))?;
    reader.read_to_string(&mut buf)?;

    let mut ciphertext: Vec<u8> = vec![];
    buf.lines().for_each(|line_str| {
        let mut bytes = general_purpose::STANDARD.decode(line_str).unwrap();
        ciphertext.append(&mut bytes);
    });

    let key = match args.passphrase {
        None => return Ok(()),
        Some(passphrase_str) => {
            let mut key_bytes: Vec<u8> = vec![];
            key_bytes.extend_from_slice(passphrase_str.as_bytes());
            key_bytes
        }
    };

    let mut cipher = Aes128Ecb::with_key(&key);
    let plaintext = cipher.decrypt(&ciphertext);
    println!("{:?}", plaintext);

    return Ok(());
}
