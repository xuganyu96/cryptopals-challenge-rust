use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::Aes128;
use cryptopals::encoding;
use std::fs;

fn main() {
    let blocksize: usize = 16;
    let ciphertext_str = fs::read_to_string("./tests/data/7.txt").unwrap();
    let answer_str = fs::read_to_string("./tests/data/7-plaintext.txt").unwrap();
    let ciphertext: Vec<u8> = ciphertext_str
        .lines()
        .map(|line| encoding::decode_base64(line).unwrap())
        .flatten()
        .collect();
    let mut plaintext: Vec<u8> = vec![];

    // build the cipher
    let cipher = Aes128::new_from_slice(b"YELLOW SUBMARINE").unwrap();

    // Decrypt the ciphertext block by block
    let nblocks = ciphertext.len() / blocksize;
    for i in 0..nblocks {
        let mut block: [u8; 16] = [0u8; 16];
        let block_start = i * blocksize;
        let block_end = (i + 1) * blocksize;
        block.copy_from_slice(&ciphertext[block_start..block_end]);
        let mut block = GenericArray::from(block);
        cipher.decrypt_block(&mut block);
        let plaintext_block = block.to_vec();

        // Remove padding from the plaintext block if it is the last block
        if i == (nblocks - 1) {
            let pad = plaintext_block.get(plaintext_block.len() - 1).unwrap();
            let pad: usize = (*pad) as usize; // the last "pad" number of bytes are pad
            let end = plaintext_block.len() - pad;
            plaintext.extend_from_slice(plaintext_block.get(0..end).unwrap());
        } else {
            plaintext.extend_from_slice(&plaintext_block);
        }
    }
    assert_eq!(String::from_utf8(plaintext).unwrap(), answer_str,);
}
