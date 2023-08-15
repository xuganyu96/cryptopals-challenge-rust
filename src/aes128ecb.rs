//! Convenient implementation of the AES-128-ECB stream cipher
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use std::error::Error;

/// The cipher itself, which maintains state of the cipher. Electrnic code book are technically
/// stateless, but for the sake of consistency with future implementation we will still use a
/// struct to wrap around the backend implementation
pub struct Aes128Ecb {
    cipher: Aes128,
}

impl Aes128Ecb {
    /// Return the cipher with the keys copied from the input.
    ///
    /// If the key is not exactly 128-bit, the returned value will be an error
    pub fn from_key(key: &[u8]) -> Result<Self, Box<dyn Error>> {
        if key.len() != 16 {
            return Err("Incorrect key length".into());
        }
        // unwrap is okay because of the length check
        let cipher = Aes128::new_from_slice(key).unwrap();

        return Ok(Self { cipher });
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        if plaintext.len() % 16 != 0 {
            todo!("Padding is not yet implemented");
        }
        let mut output: Vec<u8> = vec![];

        let nblocks = plaintext.len() / 16;
        for i in 0..nblocks {
            let mut block: [u8; 16] = [0u8; 16];
            let block_start = i * 16;
            let block_end = (i + 1) * 16;
            block.copy_from_slice(plaintext.get(block_start..block_end).unwrap());
            let mut block = GenericArray::from(block);
            self.cipher.encrypt_block(&mut block);
            let mut cipher_text = block.to_vec();
            output.append(&mut cipher_text);
        }
        // TODO: before we implement proper padding, here is a hack: for plaintext whose length is
        // a multiple of block sizes, a entire new block that consists entirely of padding needs to
        // be appended
        let block: [u8; 16] = [0x10u8; 16];
        let mut block = GenericArray::from(block);
        self.cipher.encrypt_block(&mut block);
        let mut cipher_text = block.to_vec();
        output.append(&mut cipher_text);

        return output;
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        if ciphertext.len() % 16 != 0 {
            return Err("Invalid ciphertext length".into());
        }
        let mut plaintext = vec![];

        let nblocks = ciphertext.len() / 16;
        for i in 0..nblocks {
            let mut block: [u8; 16] = [0u8; 16];
            let block_start = i * 16;
            let block_end = (i + 1) * 16;
            block.copy_from_slice(ciphertext.get(block_start..block_end).unwrap());
            let mut block = GenericArray::from(block);
            self.cipher.decrypt_block(&mut block);
            let plaintext_block = block.to_vec();

            if i == (nblocks - 1) {
                let pad = plaintext_block.get(plaintext_block.len() - 1).unwrap();
                let pad: usize = (*pad) as usize; // the last "pad" number of bytes are pad
                let end = plaintext_block.len() - pad;
                plaintext.extend_from_slice(plaintext_block.get(0..end).unwrap());
            } else {
                plaintext.extend_from_slice(&plaintext_block);
            }
        }

        return Ok(plaintext);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt() {
        let mut cipher = Aes128Ecb::from_key("0000000000000000".as_bytes()).unwrap();
        let plaintext = "0000000000000000";
        let ciphertext = cipher.encrypt(plaintext.as_bytes());

        assert_eq!(
            hex::encode(&ciphertext),
            // Result obtained from some suspicious online tool LOL
            "f95c7f6b192b22bffefd1b779933fbfc346bce0b8eed34da10f6a8fabb844494"
        );

        let decrypted_msg = cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted_msg, plaintext.as_bytes())
    }
}
