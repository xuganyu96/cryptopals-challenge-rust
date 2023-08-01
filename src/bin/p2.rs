//! https://cryptopals.com/sets/1/challenges/2
use hex;

const LHS: &str = "1c0111001f010100061a024b53535009181c";
const RHS: &str = "686974207468652062756c6c277320657965";
const ANSWER: &str = "746865206b696420646f6e277420706c6179";

fn main() {
    let lhs = hex::decode(LHS).unwrap();
    let rhs = hex::decode(RHS).unwrap();

    let xor_bytes = lhs.iter()
        .zip(rhs.iter())
        .map(|(left_byte, right_byte)| {
            let xor_byte = left_byte ^ right_byte;
            return xor_byte;
        })
        .collect::<Vec<u8>>();
    if hex::encode(xor_bytes).as_str() == ANSWER {
        println!("Conversion successful");
    }
}
