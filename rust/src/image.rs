use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use sha2::{Digest, Sha256};

pub fn sha256_file<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let mut file = File::open(path)?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];

    loop {
        let bytes_read = file.read(&mut buffer)?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    let digest = hasher.finalize();

    Ok(digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_file_works() {
        let path = "test.img";

        let hash = sha256_file(path).expect("failed to hash test file");

        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }
}