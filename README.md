This project is organized as a library crate, and individual problems are solved in the `tests` directory as integration tests on the public API of the library.

# Set 1
## Problem 1
Problem 1 is trivial if I don't try to implement the conversion by hand (and in production use I probably will not anyways). However, it is notable that the two crates I used (`hex@0.4.3` and `base64@0.21.2`) have somewhat different APIs, so I implemented a module that provides a consistent API for converting among base64, hex, and bytes:

```rust
pub mod encoding {
    /// A wrapper for hex::encode
    pub fn encode_hex(bytes: &[u8]) -> String

    /// A wrapper for hex::decode
    pub fn decode_hex(hexstr: &str) -> Result<Vec<u8>, Box<dyn Error>>

    /// A wrapper for the encoding method in base64
    pub fn encode_base64(bytes: &[u8]) -> String

    /// A wrapper for the decoding method in base64
    pub fn decode_base64(b64str: &str) -> Result<Vec<u8>, Box<dyn Error>>
}
```

## Problem 2-6
Problem 2 through 6 implement and break the classical Caesar cipher (single-byte XOR) and Vigenere cipher (repeating-key XOR). It's worth noting that Caesar cipher is a special case of the Vigenere cipher where the key size is exactly one byte, so in the end we need only one set of API to cover the use case for both ciphers

```rust
pub mod vigenere {
    pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {}
    pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {}

    /// Return an ordered list of possible key sizes
    pub fn find_keysizes(ciphertext: &[u8]) -> Vec<usize> {}

    /// Return an ordered list of possible keys
    pub fn solve_with_keysize(ciphertext: &[u8], keysize: usize) -> Vec<Vec<u8>> {}
}
```

## Problem 7-8
Problem 7-8 introduced the block cipher AES-128 operating in ECB mode. While `aes-128-ecb` is supported by `openssl`, I could not get the decryption in problem 7 to work, so I had to use the `aes@0.8.3` crate.
