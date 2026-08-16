use sha2::{Digest, Sha256};

/// Calculates SHA-256 for arbitrary bytes.
pub fn sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();

    hasher.update(data);

    let result = hasher.finalize();

    result
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_works() {
        let hash = sha256(b"hello");

        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}