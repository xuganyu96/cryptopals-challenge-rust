# Set 2

Many problems in this set are concerned with implementing and breaking the various modes of block cipher operation without referring to any specific block cipher (although AES-128 is the primary choice). This makes me want to create some kind of interface that serves as a layer of abstration, so that the solution written in this set is generic to all block ciphers.

```rust
/// A collection of methods that help extend the functionality of a block cipher
/// into a stream cipher, including padding and various modes of operation
pub trait BlockCipher {
    /// Return the block size; note that block size must fit within the range of
    /// a single byte, hence the return type u8
    fn blocksizeu8(&self) -> u8 {}

    /// Return the block size as a usize so that it works nicely with other
    /// "sizes"
    pub fn blocksize(&self) -> usize {
        return self.blocksizeu8() as usize;
    }

    /// Given a slice that is the plaintext, return a copy of the plaintext plus
    /// the appropriate padding.
    pub fn pad_from_slice(&self, plaintext: &[u8]) -> Vec<u8> {}

    /// Return True if and only if the padding on the input plaintext is valid.
    fn check_pad(&self, plaintext: &[u8]) -> bool {}

    /// Recover the unpadded message from the input plaintext
    ///
    /// If the input plaintext contains invalid padding, return error
    pub fn unpad(&self, plaintext: &[u8]) -> common::Result<&[u8]> {}

    /// Generate initialization vector for CBC mode of operation. The block
    /// block cipher is needed because we need to know how many random bytes to
    /// generate
    fn generate_iv(&self) -> Vec<u8> {}

    /// Encrypt the input plaintext using the given block cipher in ECB mode
    pub fn ecb_encrypt_from_slice(&mut self, plaintext: &[u8]) -> Vec<u8> {}

    /// Decrypt the input ciphertext, assuming that the input ciphertext is
    /// encrypted under ECB mode. If decryption fails, return error.
    pub fn ecb_decrypt_from_slice(
        &mut self,
        ciphertext: &[u8]
    ) -> common::Result<Vec<u8>> {}

    /// Using the block cipher, pad then encrypt the input using the CBC mode
    /// of operation; the ciphertext is copied into a new byte vector
    pub fn cbc_encrypt_from_slice(&mut self, plaintext: &[u8]) -> Vec<u8> {}

    /// Using hte block cipher, decrypt the input. The decrypted plaintext is
    /// copied into a new byte vector. Decryption can fail due to incorrect
    /// padding, invalid lengths, and many other reasons; if decryption failed,
    /// return error.
    pub fn cbc_decrypt_from_slice(
        &mut self,
        ciphertext: &[u8]
    ) -> common::Result<Vec<u8>> {}
}
```

## 9. PKCS#7 padding
Primitive block ciphers can only operate on fixed-sized blocks, but normal plaintext can have arbitrary lengths that are not multiples of the block size of the chosen block cipher. One way to address this is by padding the plaintext with repeating bytes where each byte encode the length of the padding.

- If plaintext length is not a multiple of the block size, then pad with `x` until it is a multiple of block size, where `x` is the number of bytes in the pad
- If plaintext length is a multiple of block size, then pad an entire additional block

Note the following constraints:

- `blocksize` should be an attribute/method of a block cipher, and the padding scheme should work regardless of the specific value
- All bytes of the pad must be the number of bytes in the pad, meaning that **when recovering the unpadded message from the padded plaintext, all last `x` bytes will be checked, and if not all of those bytes are the length of the pad, the recovery will be considered "failed"**

## 10. implement CBC
Ciphertext block chaining (CBC) is a mode of operation that extends a block cipher into a stream cipher. There are three major operations:

1. Use some randomness when generating the **initialization vector**, although cryptographic strength is probably not required
2. The encryption operation, which can only be done sequentially
3. The decryption operation, which can be done sequentially or in parallel; I will probably not implement actual "parallel decryption", but knowing how to decrypt a block using only the adjacent block sounds useful

## 10a. re-implement ECB
