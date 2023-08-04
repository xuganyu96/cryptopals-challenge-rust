//! Caesar cipher, or single-byte XOR, depending on the context
const REFERENCE_FREQUENCIES: [f64; 26] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
    0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
    0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
];

fn single_byte_xor(bytes: &[u8], key: &u8) -> Vec<u8> {
    return bytes.iter().map(|byte| byte ^ key).collect::<Vec<u8>>();
}

pub fn decrypt(ciphertext: &[u8], key: &u8) -> Vec<u8> {
    return single_byte_xor(ciphertext, key);
}

pub fn encrypt(ciphertext: &[u8], key: &u8) -> Vec<u8> {
    return single_byte_xor(ciphertext, key);
}

/// Simple encoding of the 26 lettters
pub struct EnglishFrequency {
    frequencies: [f64; 26],
}

impl EnglishFrequency {
    pub fn reference() -> Self {
        return Self {
            frequencies: REFERENCE_FREQUENCIES,
        };
    }

    pub fn mse(&self, other: &Self) -> f64 {
        let sum_squared_error = self
            .frequencies
            .iter()
            .zip(other.frequencies.iter())
            .map(|(f1, f2)| (f2 - f1) * (f2 - f1))
            .sum::<f64>();

        return sum_squared_error / 26.0;
    }

    /// Given an array that counts the number of occurrences of each letter of the English
    /// alphabet, return an equally sized array that counts the frequency of each letter by
    /// dividing each count by the sum
    fn from_counts(counts: &[usize; 26]) -> Self {
        let mut frequencies = [0.0; 26];
        let total: f64 = counts.iter().sum::<usize>() as f64;
        counts
            .iter()
            .map(|count| (*count as f64) / total)
            .enumerate()
            .for_each(|(i, frequency)| {
                frequencies[i] = frequency;
            });

        return Self { frequencies };
    }

    /// Given a byte array that is assumed to encode some String in ASCII, compute the frequency of
    /// each letter of the English alphabet. Note that it is possible that the string itself did
    /// not contain any English letter, hence it is possible that this method will not always
    /// return a frequency struct
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
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

        return Some(Self::from_counts(&counts));
    }
}

/// Given some ciphertext and some reference English letter frequency, return (up to) the n best
/// keys for decrypting the input ciphertext. The best decryption is the one whose plaintext's
/// frequencies have the lowest MSE against the reference frequencies
///
/// If ascii_only is set to true, then decryption that contains bytes outside the printable ASCII
/// range will be excluded
///
/// If n is 0, then all suitable keys will be returned
pub fn n_best_keys(
    ciphertext: &[u8],
    reference: &EnglishFrequency,
    n: usize,
    ascii_only: bool,
) -> Vec<u8> {
    let mut key_scores = (0u8..=255u8) // all possible keys
        .filter_map(|key| {
            let plaintext = decrypt(ciphertext, &key);
            let all_printable_ascii = plaintext
                .iter()
                .all(|byte| (32..=126).contains(byte) || *byte == 10 || *byte == 9);
            if ascii_only && !all_printable_ascii {
                return None;
            }

            let mse = match EnglishFrequency::from_bytes(&plaintext) {
                None => return None,
                Some(frequencies) => frequencies.mse(reference),
            };
            return Some((key, mse));
        })
        .collect::<Vec<(u8, f64)>>();
    key_scores.sort_by(|f1, f2| {
        let (_, f1) = f1;
        let (_, f2) = f2;
        return f1.partial_cmp(f2).unwrap();
    });
    let best_keys = match n {
        0 => key_scores.iter().map(|(key, _)| *key).collect::<Vec<u8>>(),
        _ => key_scores
            .iter()
            .take(n)
            .map(|(key, _)| *key)
            .collect::<Vec<u8>>(),
    };
    return best_keys;
}
