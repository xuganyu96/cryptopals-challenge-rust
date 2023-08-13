//! Convenient implementation of the AES-128-ECB stream cipher

/// The cipher itself, which maintains state of the cipher. Electrnic code book are technically
/// stateless, but for the sake of consistency with future implementation we will still use a
/// struct to wrap around the backend implementation
pub struct Aes128Ecb {}

impl Aes128Ecb {
    pub fn new() -> Self {
        todo!();
    }

    pub fn set_key(&mut self, key: &[u8]) {
        println!("Key set to {:?}", key);
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        return plaintext.to_vec();
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        return ciphertext.to_vec();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt() {
        let mut cipher = Aes128Ecb::new();
        cipher.set_key(b"YELLOW SUBMARINE");
        let plaintext = "Hello, world!";
        let ciphertext = cipher.encrypt(plaintext.as_bytes());

        assert_eq!(
            hex::encode(ciphertext),
            "d1aa4f6578926542fbb6dd876cd2050860fa36707e45f499dba0f25b922301a5"
        );
    }
}
