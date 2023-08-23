# Set 1
Problem 1 through 6 all lead to the implementation and breaking of the Vigenere cipher. Although there are two separate single-byte XOR problems (Caesar cipher), they are special cases of repeating-key XOR. As such, a single set of API for the Vigenere cipher is used for all problems.

```rust
fn encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8>

fn decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8>

/// Return an ordered list of possible key sizes, where the value at lower index
/// is the more likely key size
fn find_keysize(ciphertext: &[u8]) -> Vec<u8>

/// Return an ordered list of possible keys with the given input key size
fn solve_with_keysize(ciphertext: &[u8], keysize: usize) -> Vec<Vec<u8>>
```

For problem 7 and 8, we need to implement AES128 in ECB mode. The public API of the `aes128ecb` module is as follows:

```rust
/// There are some caveats with allowablw ciphertext sizes and key sizes:
/// ciphertext must be a multiple of 16 bytes, and key size must be exactly 16
/// bytes
fn decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8>
```

Encryption will be omitted for now, knowing that in set 2 we will implement PKCS padding.