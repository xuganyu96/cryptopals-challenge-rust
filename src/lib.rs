pub mod aes128ecb;
pub mod caesar;
pub mod encoding;
pub(crate) mod english;
pub mod vigenere;

pub mod common {
    use core::result;
    use std::collections::HashMap;
    use std::error::Error;
    use std::fs::File;
    use std::io::{self, Read};

    pub type Result<T> = result::Result<T, Box<dyn Error>>;

    /// Return a reader that reads from the file specified by the input path; if no input path is
    /// given, open a reader on stdin
    pub fn open(path: Option<String>) -> Result<Box<dyn Read>> {
        return match path {
            Some(filepath) => {
                let file = File::open(filepath)?;
                let reader = Box::new(file);
                Ok(reader)
            }
            None => {
                let reader = Box::new(io::stdin());
                Ok(reader)
            }
        };
    }

    /// Given some ciphertext, analyze the frequency of blocks (of the given size). Return a hash
    /// map that maps "blocks of ciphertext" to the number of times they appear in the input
    /// ciphertext
    pub fn count_block_frequency(
        ciphertext: &[u8],
        blocksize: usize,
    ) -> Result<HashMap<Vec<u8>, usize>> {
        if ciphertext.len() % blocksize != 0 {
            return Err("Invalid ciphertext length".into());
        }

        let mut counts = HashMap::new();

        let mut i = 0;
        while (i + 1) * blocksize <= ciphertext.len() {
            let block_start = i * blocksize;
            let block_end = (i + 1) * blocksize;
            let block = ciphertext.get(block_start..block_end).unwrap().to_vec();
            let count = counts.get(&block).unwrap_or(&0);
            counts.insert(block, count + 1);
            i += 1;
        }

        return Ok(counts);
    }
}
