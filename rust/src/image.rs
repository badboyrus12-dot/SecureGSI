use sha2::{Digest, Sha256};
use std::fs::File;
use std::io;

#[cfg(any(unix, test))]
use std::io::Read;

/// Hashes data from any reader.
///
/// Compiled when:
/// - building for Unix/Android, where sha256_fd() uses it;
/// - running tests, where Cursor is used.
#[cfg(any(unix, test))]
fn sha256_reader<R: Read>(reader: &mut R) -> io::Result<String> {
    let mut hasher = Sha256::new();

    /*
     * Fixed-size stack buffer:
     * - no allocation proportional to input size;
     * - bounded memory usage while hashing arbitrarily large files.
     */
    let mut buffer = [0_u8; 1024 * 1024];

    loop {
        let bytes_read = reader.read(&mut buffer)?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    let digest = hasher.finalize();

    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(any(unix, test))]
fn read_header_reader<R: Read>(reader: &mut R, max_len: usize) -> io::Result<Vec<u8>> {
    if max_len == 0 {
        return Ok(Vec::new());
    }

    let mut buffer = vec![0_u8; max_len];
    let bytes_read = reader.read(&mut buffer)?;
    buffer.truncate(bytes_read);

    Ok(buffer)
}

/// Calculates SHA-256 from an already-owned File.
///
/// Taking File by value makes descriptor ownership explicit in the type system:
/// the descriptor is always closed exactly once when this function returns.
#[cfg(unix)]
pub fn sha256_file(mut file: File) -> io::Result<String> {
    sha256_reader(&mut file)
}

#[cfg(not(unix))]
pub fn sha256_file(_file: File) -> io::Result<String> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "file descriptors are only supported on Unix/Android",
    ))
}

/// Reads at most `max_len` bytes from an already-owned File.
///
/// File ownership is acquired before any early return, so even `max_len == 0`
/// cannot leak the duplicated descriptor.
#[cfg(unix)]
pub fn read_header_file(mut file: File, max_len: usize) -> io::Result<Vec<u8>> {
    read_header_reader(&mut file, max_len)
}

#[cfg(not(unix))]
pub fn read_header_file(_file: File, _max_len: usize) -> io::Result<Vec<u8>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "file descriptors are only supported on Unix/Android",
    ))
}

/// Calculates SHA-256 of an already-owned file descriptor.
///
/// # Safety
///
/// `fd` must be a valid file descriptor whose ownership has been transferred
/// to this function.
///
/// On Unix/Android `File::from_raw_fd()` takes ownership of `fd`, so the
/// descriptor is closed exactly once when `file` is dropped.
///
/// Callers that need to keep their original descriptor must `dup()` it first.
///
/// New code should prefer `sha256_file()`, which carries ownership in the type
/// system and therefore requires no unsafe call at the caller.
#[cfg(unix)]
#[expect(
    dead_code,
    reason = "legacy ownership-transfer API retained for compatibility; new code uses sha256_file"
)]
pub unsafe fn sha256_fd(fd: i32) -> io::Result<String> {
    use std::os::fd::FromRawFd;

    // SAFETY: The function contract requires ownership of a valid file
    // descriptor. from_raw_fd takes that ownership and File closes it once.
    let file = unsafe { File::from_raw_fd(fd) };

    sha256_file(file)
}

#[cfg(not(unix))]
#[expect(
    dead_code,
    reason = "legacy ownership-transfer API retained for compatibility; new code uses sha256_file"
)]
pub unsafe fn sha256_fd(_fd: i32) -> io::Result<String> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "file descriptors are only supported on Unix/Android",
    ))
}

/// Reads at most `max_len` bytes from an already-owned image FD.
///
/// # Safety
///
/// `fd` must be a valid file descriptor whose ownership has been transferred
/// to this function.
///
/// `File::from_raw_fd()` takes ownership of the descriptor and closes it when
/// the `File` is dropped.
///
/// New code should prefer `read_header_file()`, which carries ownership in the
/// type system and therefore requires no unsafe call at the caller.
#[cfg(unix)]
#[expect(
    dead_code,
    reason = "legacy ownership-transfer API retained for compatibility; new code uses read_header_file"
)]
pub unsafe fn read_header_fd(fd: i32, max_len: usize) -> io::Result<Vec<u8>> {
    use std::os::fd::FromRawFd;

    // SAFETY: The function contract requires ownership of a valid file
    // descriptor. Ownership is acquired before the zero-length fast path, so
    // every return path closes the descriptor exactly once.
    let file = unsafe { File::from_raw_fd(fd) };

    read_header_file(file, max_len)
}

#[cfg(not(unix))]
#[expect(
    dead_code,
    reason = "legacy ownership-transfer API retained for compatibility; new code uses read_header_file"
)]
pub unsafe fn read_header_fd(_fd: i32, _max_len: usize) -> io::Result<Vec<u8>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "file descriptors are only supported on Unix/Android",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_reader_works() {
        let mut data = std::io::Cursor::new(b"AegisDroid");

        let hash = sha256_reader(&mut data).expect("failed to hash test data");

        assert_eq!(hash.len(), 64,);

        assert!(
            hash.chars()
                .all(|character| { character.is_ascii_hexdigit() },),
        );
    }

    #[test]
    fn zero_header_length_is_valid() {
        assert_eq!(0_usize, 0_usize,);
    }

    #[test]
    fn zero_header_length_reads_nothing() {
        let mut data = std::io::Cursor::new(b"HEADER");

        let header = read_header_reader(&mut data, 0).expect("zero-length read");

        assert!(header.is_empty());
        assert_eq!(data.position(), 0);
    }
}
