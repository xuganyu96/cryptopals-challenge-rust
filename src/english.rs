//! A collection of methods and constants that help with ranking and filtering the outputs of
//! decryptions. Most of them operate on UTF-8 strings and characters
use std::collections::{HashMap, HashSet};

/// credits: https://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
const ALPHABETIC_FREQUENCIES: [(char, f64); 26] = [
    ('e', 0.1202),
    ('t', 0.091),
    ('a', 0.0812),
    ('o', 0.0768),
    ('i', 0.0731),
    ('n', 0.0695),
    ('s', 0.0628),
    ('r', 0.0602),
    ('h', 0.0592),
    ('d', 0.0432),
    ('l', 0.0398),
    ('u', 0.0288),
    ('c', 0.0271),
    ('m', 0.0261),
    ('f', 0.0230),
    ('y', 0.0211),
    ('w', 0.0209),
    ('g', 0.0203),
    ('p', 0.0182),
    ('b', 0.0149),
    ('v', 0.0111),
    ('k', 0.0069),
    ('x', 0.0017),
    ('q', 0.0011),
    ('j', 0.0010),
    ('z', 0.0007),
];

/// Some arbitrary set of invalid characters in plaintext
const INVALID_CHARS: [char; 1] = ['\0'];

/// Return True iff the percentage of English alphabet letter in the input string is at or greater
/// than the input threshold. If the input string is empty, return True
pub(crate) fn eng_char_threshold(plaintext: &str, threshold: f64) -> bool {
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

/// Return True iff input string contains invalid characters, as defined by the constant
pub(crate) fn contains_invalid_chars(plaintext: &str) -> bool {
    return plaintext
        .chars()
        .any(|char_| INVALID_CHARS.contains(&char_));
}

/// Count the percentage frequency of each unique character in the input string
/// Note that this counting is case-insensitive. All uppercase letters will be automatically
/// converted to lowercase
pub(crate) fn char_frequency(plaintext: &str) -> HashMap<char, f64> {
    let mut frequencies = HashMap::new();
    let nchars = plaintext.chars().count() as f64;
    // count before dividing to prevent underflow
    plaintext.to_ascii_lowercase().chars().for_each(|ptchar| {
        let count = frequencies.get(&ptchar).unwrap_or(&0.);
        let count = *count + 1.0;
        frequencies.insert(ptchar, count);
    });
    frequencies.values_mut().for_each(|val| {
        *val = (*val) / nchars;
    });

    return frequencies;
}

/// Compare frequencies and compute mean-square-error
pub(crate) fn char_mse(lhs: &HashMap<char, f64>, rhs: &HashMap<char, f64>) -> f64 {
    let mut unique_keys: HashSet<char> = HashSet::new();
    let mut se_sum = 0.0;

    lhs.keys().for_each(|key| {
        unique_keys.insert(*key);
    });
    rhs.keys().for_each(|key| {
        unique_keys.insert(*key);
    });
    unique_keys.iter().for_each(|key| {
        let lhs_f = lhs.get(key).unwrap_or(&0.0);
        let rhs_f = rhs.get(key).unwrap_or(&0.0);
        let se = (lhs_f - rhs_f) * (lhs_f - rhs_f);
        se_sum += se;
    });
    let n_unique_keys = unique_keys.iter().count() as f64;

    return se_sum / n_unique_keys;
}

pub(crate) fn reference_frequencies() -> HashMap<char, f64> {
    let mut frequencies = HashMap::new();
    ALPHABETIC_FREQUENCIES.iter().for_each(|(ptchar, freq)| {
        frequencies.insert(*ptchar, *freq);
    });

    return frequencies;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eng_char_treshold() {
        // there are 10 alphabet chars and 2 non-alphabet chars
        let plaintext: &str = "Hello, world";
        assert!(eng_char_threshold(plaintext, 0. / 12.));
        assert!(eng_char_threshold(plaintext, 10. / 12.));
        assert!(!eng_char_threshold(plaintext, 11. / 12.));
    }
}
