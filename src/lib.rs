pub mod caesar;
pub mod vigenere;

pub mod common {
    use std::error::Error;
    use std::fs::File;
    use std::io::{self, Read};

    /// Return a reader that reads from the file specified by the input path; if no input path is
    /// given, open a reader on stdin
    pub fn open(path: Option<String>) -> Result<Box<dyn Read>, Box<dyn Error>> {
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
