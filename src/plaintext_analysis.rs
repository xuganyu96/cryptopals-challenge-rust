//! A collection of methods and constants that help with ranking and filtering the outputs of
//! decryptions. Most of them operate on UTF-8 strings and characters

/// Return True iff the input bytes form valid UTF-8 strings according to Rust String
pub fn is_valid_utf8(bytes: &[u8]) -> bool {
    return String::from_utf8(bytes.to_vec()).is_ok();
}

/// Return True iff the percentage of English alphabet letter in the input string is at or greater
/// than the input threshold. If the input string is empty, return True
pub fn eng_char_threshold(plaintext: &str, threshold: f64) -> bool {
    if plaintext.len() == 0 {
        return true;
    }

    let count: usize = plaintext
        .chars()
        .map(|ptchar| {
            if ptchar.is_alphabetic() {
                return 1usize;
            }
            return 0usize;
        })
        .sum();
    let total: usize = plaintext.chars().count();
    let count_threshold = f64::round((total as f64) * threshold) as usize;
    return count >= count_threshold;
}
