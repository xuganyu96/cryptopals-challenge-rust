//! https://cryptopals.com/sets/1/challenges/3
use hex;

const INPUTS: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
const REFERENCE_FREQUENCIES: [f64; 26] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
    0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
    0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
];

fn decrypt(ciphertext: &[u8], key: &u8) -> Vec<u8> {
    return ciphertext
        .iter()
        .map(|byte| byte ^ key)
        .collect::<Vec<u8>>();
}

/// True if the byte can encode a printable ASCII character
fn is_ascii(byte: &u8) -> bool {
    return (32u8..127u8).contains(byte);
}

/// Simple encoding of the 26 lettters
struct EnglishFrequency {
    frequencies: [f64; 26],
}

impl EnglishFrequency {
    fn mse(&self, other: &Self) -> f64 {
        let sum_squared_error = self
            .frequencies
            .iter()
            .zip(other.frequencies.iter())
            .map(|(f1, f2)| (f2 - f1) * (f2 - f1))
            .sum::<f64>();

        return sum_squared_error / 26.0;
    }

    fn from_counts(counts: &[usize; 26]) -> Self {
        let total: f64 = counts.iter().sum::<usize>() as f64;
        let frequencies_vec = counts
            .iter()
            .map(|count| (*count as f64) / total)
            .collect::<Vec<f64>>();
        let mut frequencies = [0.0; 26];
        frequencies.copy_from_slice(&frequencies_vec);

        return Self { frequencies };
    }
}

fn count_letters(bytes: &[u8]) -> Option<[usize; 26]> {
    let mut counts = [0usize; 26];
    bytes.iter().for_each(|byte| {
        if (65..=90).contains(byte) {
            counts[usize::from(byte - 65)] += 1;
        } else if (97..=122).contains(byte) {
            counts[usize::from(byte - 97)] += 1;
        }
    });

    if counts.iter().sum::<usize>() == 0 {
        return None;
    }

    return Some(counts);
}

/// ASCII test alone is enough to delimiate possible keys to human scale
fn main() {
    let inputs = hex::decode(INPUTS).unwrap();
    let ref_frequencies = EnglishFrequency {
        frequencies: REFERENCE_FREQUENCIES,
    };

    let mut x = (0u8..=255u8)
        .filter_map(|key| {
            let plaintext = decrypt(&inputs, &key);
            let all_ascii = plaintext.iter().all(|byte| is_ascii(byte));
            if !all_ascii {
                return None;
            }
            let counts = count_letters(&plaintext);
            if counts.is_none() {
                return None;
            }
            let counts = counts.unwrap();
            let frequencies = EnglishFrequency::from_counts(&counts);
            let mse = frequencies.mse(&ref_frequencies);
            match String::from_utf8(plaintext) {
                Ok(plaintext_str) => Some((plaintext_str, mse)),
                Err(_) => None,
            }
        })
        .collect::<Vec<(String, f64)>>();
    x.sort_by(|elem1, elem2| {
        let (_, f1) = elem1;
        let (_, f2) = elem2;
        return f1.partial_cmp(f2).unwrap();
    });

    x.iter().take(3).for_each(|elem| println!("{:?}", elem));
}
