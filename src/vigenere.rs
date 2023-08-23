//! The Vigenere cipher
//! Generalized to work with bytes
use crate::english;
use std::error::Error;

fn repeating_key_xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.len() == 0 {
        return data.to_vec();
    }
    return data
        .iter()
        .enumerate()
        .map(|(i, byte)| {
            let key_byte = key.get(i % key.len()).unwrap();
            return byte ^ key_byte;
        })
        .collect::<Vec<u8>>();
}

pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    return repeating_key_xor(plaintext, key);
}

pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    return repeating_key_xor(ciphertext, key);
}

/// Count the number of bits that are 1 in a byte
fn sum_bits(mut byte: u8) -> usize {
    let mut count = 0;

    while byte != 0 {
        count += 1;
        byte = byte & (byte - 1);
    }

    return count;
}

/// The edit distance/hamming distance is the number of differing bits.
/// If two byte strings are not the same length, return Error
fn hamming(lhs: &[u8], rhs: &[u8]) -> Result<usize, Box<dyn Error>> {
    if lhs.len() != rhs.len() {
        return Err("Strings of unequal lengths cannot be compared".into());
    }

    let sum = lhs
        .iter()
        .zip(rhs.iter())
        .map(|(b1, b2)| sum_bits(b1 ^ b2))
        .sum::<usize>();
    return Ok(sum);
}

/// Evaluate the score of a certain key size by finding the hamming distance between the first
/// batch of bytes against the second batch of bytes, where the two batches each contains key_size
/// number of bytes
fn keysize_score(ciphertext: &[u8], keysize: usize) -> Result<f64, Box<dyn Error>> {
    if 2 * keysize > ciphertext.len() {
        return Err("Key size is too large".into());
    }
    let mut i: usize = 0;
    let mut sum: f64 = 0.;
    while (i + 2) * keysize <= ciphertext.len() {
        let lhs = ciphertext.get((i * keysize)..((i + 1) * keysize)).unwrap();
        let rhs = ciphertext
            .get(((i + 1) * keysize)..((i + 2) * keysize))
            .unwrap();
        let dist = hamming(lhs, rhs)?;
        let avg = (dist as f64) / (keysize as f64);
        sum += avg;
        i += 1;
    }
    // Unwrap is okay after the size check
    let avg = sum / (i as f64);

    return Ok(avg);
}

/// Return an ordered list of possible key sizes
pub fn find_keysizes(ciphertext: &[u8]) -> Vec<usize> {
    let max = ciphertext.len() / 2;
    let mut scores = (1..=max)
        .filter_map(|keysize| match keysize_score(ciphertext, keysize) {
            Ok(score) => Some((keysize, score)),
            Err(_) => None,
        })
        .collect::<Vec<(usize, f64)>>();

    scores.sort_by(|elem1, elem2| {
        let (_, score1) = elem1;
        let (_, score2) = elem2;
        return score1.partial_cmp(score2).unwrap();
    });

    return scores
        .into_iter()
        .map(|(keysize, _score)| keysize)
        .collect();
}

/// Return the most probably key with the given keysize. If no such key can be found, return None
///
/// The best key is obtained byte by byte. To obtain the partial key at byte k, first obtain the
/// partial ciphertext by collecting every kth byte of the original ciphertext, then use frequency
/// analysis
pub fn solve_with_keysize(ciphertext: &[u8], keysize: usize) -> Option<Vec<u8>> {
    let mut key = vec![0u8; keysize];
    // TODO: if keysize greater than 1, then the partial ciphertext can follow a looser threshold
    // since partial plaintext is probably not natural English
    let mut threshold = 0.8;
    if keysize > 1 {
        threshold = 0.5;
    }

    for k in 0..keysize {
        let partial_ciphertext: Vec<u8> = ciphertext
            .iter()
            .enumerate()
            .filter_map(|(i, byte)| {
                if i % keysize == k {
                    return Some(*byte);
                }
                return None;
            })
            .collect();
        let partial_keys = solve_caesar(&partial_ciphertext, threshold);
        if partial_keys.len() == 0 {
            return None;
        }
        let (partial_key, _) = partial_keys.get(0).unwrap();
        key[k] = *partial_key;
    }

    return Some(key);
}

/// Solve a Caesar cipher, return the n best keys alongside their scores, where lower numerical
/// values correspond to a better key.
///
/// Note that this implementation currently filters decryptions based on the percentage of English
/// charactersand as well as possible invalid characters, so it is possible that the returned
/// vector is empty.
fn solve_caesar(ciphertext: &[u8], threshold: f64) -> Vec<(u8, f64)> {
    let mut keys = (0u8..=255u8)
        .filter_map(|key| {
            let plaintext = decrypt(ciphertext, &[key]);
            let plaintext_str = match String::from_utf8(plaintext) {
                Err(_) => return None,
                Ok(plaintext_str) => plaintext_str,
            };
            if !english::eng_char_threshold(&plaintext_str, threshold)
                || english::contains_invalid_chars(&plaintext_str)
            {
                // TODO: the choice of the threshold feels arbitrary; should be more systematic
                return None;
            }
            let frequencies = english::char_frequency(&plaintext_str);
            let mse = english::char_mse(&frequencies, &english::reference_frequencies());

            return Some((key, mse));
        })
        .collect::<Vec<(u8, f64)>>();
    keys.sort_by(|elem1, elem2| {
        let (_, mse1) = elem1;
        let (_, mse2) = elem2;
        return mse1.partial_cmp(mse2).unwrap();
    });

    return keys;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sum_bits() {
        assert_eq!(sum_bits(0), 0);
        assert_eq!(sum_bits(1), 1);
        assert_eq!(sum_bits(2), 1);
        assert_eq!(sum_bits(4), 1);
        assert_eq!(sum_bits(8), 1);
        assert_eq!(sum_bits(16), 1);
        assert_eq!(sum_bits(32), 1);
        assert_eq!(sum_bits(64), 1);
        assert_eq!(sum_bits(128), 1);
        assert_eq!(sum_bits(255), 8);
        assert_eq!(sum_bits(254), 7);
    }

    #[test]
    fn test_hamming() {
        assert_eq!(
            hamming("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()).unwrap(),
            37
        );
    }

    #[test]
    fn test_keysize_score() {
        // we know that "this is a test" and "wokka wokka!!!" have edit distance of 37
        // each has length 14, so the average distance should be 37 / 14
        assert_eq!(
            keysize_score("this is a testwokka wokka!!!".as_bytes(), 14).unwrap(),
            (37usize as f64) / (14 as f64),
        );
    }
}
