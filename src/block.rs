//! Functions used for converting block ciphers primitives into block ciphers that can encrypt and
//! decrypt messages of arbitrary sizes.
use crate::common;

/// Given a plaintext of arbitrary size, return a padded plaintext that is a multiple of the input
/// blocksize (typicaly 128 bits). Each byte of the padding is the number of bytes between the
/// plaintext's size and the next multiple of block size. If the plaintext is an exact multiple of
/// block size, then pad an entire new block where each byte is the block size
///
/// Note that blocksize is u8 because blocksize must fit into the value range of a byte
pub fn pkcs7(plaintext: &[u8], blocksize: u8) -> Vec<u8> {
    let blockusize: usize = blocksize.into();
    let mut pad: Vec<u8> = Vec::new();

    let pad_val = blockusize - (plaintext.len() % blockusize);
    for _ in 0..pad_val {
        pad.push(pad_val as u8);
    }

    let mut padded_plaintext: Vec<u8> = Vec::new();
    padded_plaintext.extend_from_slice(plaintext);
    padded_plaintext.append(&mut pad);
    return padded_plaintext;
}

/// Recover the message from the padded message without copying.
///
/// This function will check that the padded plaintext is not empty and is a multiple of the input
/// blocksize
pub fn pkcs7_unpad(padded_plaintext: &[u8], blocksize: u8) -> common::Result<&[u8]> {
    let blockusize: usize = blocksize.into();
    if (padded_plaintext.len() == 0) || (padded_plaintext.len() % blockusize != 0) {
        return Err("Invalid plaintext length".into());
    }

    let plaintext_start = 0;
    let mut plaintext_stop = padded_plaintext.len();
    let pad_val = padded_plaintext.get(padded_plaintext.len() - 1).unwrap();
    if (*pad_val as usize) > padded_plaintext.len() {
        return Err("Invalid padding".into());
    }
    let pad_range = (padded_plaintext.len() - *pad_val as usize)..padded_plaintext.len();
    for val in padded_plaintext.get(pad_range).unwrap() {
        if *val != *pad_val {
            return Err("Invalid padding".into());
        }
    }
    plaintext_stop -= *pad_val as usize;

    return Ok(padded_plaintext
        .get(plaintext_start..plaintext_stop)
        .unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs7() {
        let plaintext: [u8; 0] = [];
        let padded = pkcs7(&plaintext, 16);
        assert_eq!(padded, [16u8; 16]);
    }

    #[test]
    fn tst_pkcs7_unpad() {
        let padded = [16u8; 16];
        let plaintext = pkcs7_unpad(&padded, 16);
        assert_eq!(plaintext.unwrap(), &[0u8; 0]);
    }
}
