//! The Vigenere cipher
//! Generalized to work with bytes

/// Given a finitely sized key, the repeating key can be used to repeat through the bytes
/// indefinitely
pub struct RepeatingKey<'a> {
    key: &'a [u8],
    cursor: usize,
}

impl<'a> RepeatingKey<'a> {
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
}
