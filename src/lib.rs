pub mod block;
pub mod caesar;
pub mod dh;
pub mod encoding;
pub(crate) mod english;
pub mod vigenere;

pub mod common {
    use core::result;
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
}
