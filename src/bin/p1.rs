//! https://cryptopals.com/sets/1/challenges/1
//!
//! While it would be a lot of fun implementing the conversion among hex, bytes, and base64, for
//! the sake of moving onto the actual cryptographic challenges more quickly, external crates will
//! be used.
//!
//! TODO: Implement the conversion by hand
use base64;
use base64::{
    engine::general_purpose,
    Engine as _,
};
use hex;

const INPUTS: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
const ANSWER: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

fn main() {
    let bytes = hex::decode(INPUTS).unwrap(); // TODO: remove this unwrap
    let b64 = general_purpose::STANDARD.encode(bytes);
    if b64.as_str() == ANSWER {
        println!("Conversion successful");
    }
}
