//! The Vigenere cipher
//! Generalized to work with bytes
use std::error::Error;

/// Given a finitely sized key, the repeating key can be used to repeat through the bytes
/// indefinitely
pub struct RepeatingKey<'a> {
    key: &'a [u8],
    cursor: usize,
}

impl<'a> RepeatingKey<'a> {
    /// Given a key size (in number of bytes), return an iterator that iterates through all
    /// possible RepeatingKey whose root key has matching sizes.
    ///
    /// A quick sanity check: for size = n, the iterator should contain (2 ^ 8n) items
    pub fn generate(size: usize) -> Box<dyn Iterator<Item = Self>> {
        todo!();
    }

    pub fn new(key: &'a [u8]) -> Self {
        Self { key, cursor: 0 }
    }

    /// An empty key is allowed. Calling encrypt/decrypt with an empty key will simply copy the
    /// inputs bytes to the output
    pub fn is_empty(&self) -> bool {
        return self.key.len() == 0;
    }
}

impl<'a> Iterator for RepeatingKey<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_empty() {
            return None;
        }
        let next_byte = self.key.get(self.cursor).unwrap();
        self.cursor = (self.cursor + 1) % self.key.len();
        return Some(*next_byte);
    }
}

pub fn encrypt(plaintext: &[u8], key: RepeatingKey) -> Vec<u8> {
    if key.is_empty() {
        return plaintext.to_vec();
    }
    return plaintext
        .iter()
        .zip(key.take(plaintext.len()))
        .map(|(lhs, rhs)| (*lhs) ^ rhs)
        .collect::<Vec<u8>>();
}

pub fn decrypt(ciphertext: &[u8], key: RepeatingKey) -> Vec<u8> {
    if key.is_empty() {
        return ciphertext.to_vec();
    }
    return ciphertext
        .iter()
        .zip(key.take(ciphertext.len()))
        .map(|(lhs, rhs)| (*lhs) ^ rhs)
        .collect::<Vec<u8>>();
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
    // Unwrap is okay after the size check
    let lhs = ciphertext.get(0..keysize).unwrap();
    let rhs = ciphertext.get(keysize..(2 * keysize)).unwrap();
    let dist = hamming(lhs, rhs)?;
    let avg = (dist as f64) / (keysize as f64);

    return Ok(avg);
}

/// Return a list of possible key sizes sorted by their keysize score
/// Key size with a lower score (a lower hamming distance) will have a higher ranking since it is
/// the more likely key.
///
/// If the ciphertext is too short even for a keysize of 1, the list will be empty
pub fn rank_keysizes(ciphertext: &[u8]) -> Vec<(usize, f64)> {
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

    return scores;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeat_key() {
        let root_key: Vec<u8> = vec![0, 1, 2];
        let key = RepeatingKey::new(&root_key);
        let bytes = key.take(5).collect::<Vec<u8>>();
        assert_eq!(bytes, vec![0, 1, 2, 0, 1]);
    }

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
