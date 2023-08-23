This project is organized as a library crate, and individual problems are solved in the `tests` directory as integration tests on the public API of the library.

# Set 1
## Problem 1
Problem 1 is trivial if I don't try to implement the conversion by hand (and in production use I probably will not anyways). However, it is notable that the two crates I used (`hex@0.4.3` and `base64@0.21.2`) have somewhat different APIs, so I implemented a module that provides a consistent API for converting among base64, hex, and bytes:

## Problem 2-6
```rust
pub mod encoding {
    pub fn encode_hex(bytes: &[u8]) -> String
    pub fn decode_hex(hexstr: &str) -> Result<Vec<u8>, Box<dyn Error>>
    pub fn encode_base64(bytes: &[u8]) -> String
    pub fn decode_base64(b64str: &str) -> Result<Vec<u8>, Box<dyn Error>>
}
```

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

Since the plaintext is English, frequency analysis on the English language is implemented in the `english` module:

```rust
pub mod english {
    /// Return True iff the input bytes form valid UTF-8 strings according to Rust String
    pub fn is_valid_utf8(bytes: &[u8]) -> bool {}

    /// Return True iff the percentage of English alphabet letter in the input string is at or greater
    /// than the input threshold. If the input string is empty, return True
    pub fn eng_char_threshold(plaintext: &str, threshold: f64) -> bool {}

    /// Return True iff input string contains invalid characters, as defined by a constant in the module
    pub fn contains_invalid_chars(plaintext: &str) -> bool {}

    /// Count the percentage frequency of each unique character in the input string
    /// Note that this counting is case-insensitive. All uppercase letters will be automatically
    /// converted to lowercase
    pub fn char_frequency(plaintext: &str) -> HashMap<char, f64> {}

    /// Compare frequencies and compute mean-square-error
    pub fn char_mse(lhs: &HashMap<char, f64>, rhs: &HashMap<char, f64>) -> f64 {}

    /// Return the frequency mapping, as defined by a constant in the module
    pub fn reference_frequencies() -> HashMap<char, f64> {}
}
```
