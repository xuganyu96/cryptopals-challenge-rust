//! https://cryptopals.com/sets/1/challenges/3
use hex;

const INPUTS: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

fn decrypt(ciphertext: &[u8], key: &u8) -> Vec<u8> {
    return ciphertext.iter()
        .map(|byte| byte ^ key)
        .collect::<Vec<u8>>();
}

/// The value at index i encodes the frequency as fraction between 0 and 1
struct AsciiFrequencies {
    frequencies: [f64; 256],
}

impl AsciiFrequencies {
    fn new() -> Self {
        return Self {
            frequencies: [0.0; 256],
        };
    }

    fn mean_squared_difference(&self, other: &Self) -> f64 {
        return self.frequencies.iter()
            .zip(other.frequencies.iter())
            .map(|(f1, f2)| (f2 - f1) * (f2 - f1))
            .sum();
    }
}

fn main() {
    let inputs = hex::decode(INPUTS).unwrap();
    // TODO: implement frequency analysis
    for key in 0u8..=255u8 {
        let plaintext = decrypt(&inputs, &key);
        let outputs = String::from_utf8(plaintext);
        if outputs.is_ok() {
            println!("{outputs:?}");
        }
    }
}
