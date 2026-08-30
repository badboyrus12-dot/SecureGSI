use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use rand_core::{OsRng, RngCore};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

const SECURITY_DIR: &str = "security";
const VERIFIER_FILE: &str = "duress.phc";
const MAX_VERIFIER_BYTES: u64 = 4 * 1024;

fn verifier_path(files_dir: &Path) -> PathBuf {
    files_dir.join(SECURITY_DIR).join(VERIFIER_FILE)
}

fn crypto_error(message: impl ToString) -> io::Error {
    io::Error::other(message.to_string())
}

fn validate_files_dir(files_dir: &Path) -> io::Result<()> {
    if files_dir.as_os_str().is_empty()
        || !files_dir.is_absolute()
        || files_dir == Path::new("/")
        || files_dir
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsafe filesDir",
        ));
    }

    let metadata = fs::symlink_metadata(files_dir)?;

    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "filesDir must be a real directory",
        ));
    }

    Ok(())
}

fn validate_security_dir(security_dir: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(security_dir)?;

    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "security directory is not a real directory",
        ));
    }

    Ok(())
}

fn temporary_verifier_path(security_dir: &Path) -> PathBuf {
    let mut random_id = [0_u8; 16];
    OsRng.fill_bytes(&mut random_id);

    let id = random_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    security_dir.join(format!(".{VERIFIER_FILE}.{id}.tmp"))
}

fn write_verifier_atomically(security_dir: &Path, value: &[u8]) -> io::Result<PathBuf> {
    let temporary_path = temporary_verifier_path(security_dir);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(&temporary_path)?;

    let write_result = (|| -> io::Result<()> {
        file.write_all(value)?;
        file.sync_all()?;
        Ok(())
    })();

    drop(file);

    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }

    Ok(temporary_path)
}

fn read_verifier(files_dir: &Path) -> io::Result<Option<Zeroizing<String>>> {
    let path = verifier_path(files_dir);

    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };

    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "duress verifier is not a regular file",
        ));
    }

    if metadata.len() > MAX_VERIFIER_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "duress verifier is unexpectedly large",
        ));
    }

    let verifier = fs::read_to_string(path)?;

    if verifier.len() as u64 > MAX_VERIFIER_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "duress verifier is unexpectedly large",
        ));
    }

    Ok(Some(Zeroizing::new(verifier)))
}

/// Configures the Duress PIN.
///
/// The PIN itself is never written to disk. Only an Argon2id PHC verifier is
/// persisted in the application's private files directory.
pub fn configure(files_dir: &Path, pin: &[u8]) -> io::Result<()> {
    validate_files_dir(files_dir)?;

    if !(4..=64).contains(&pin.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Duress PIN must be 4..64 bytes",
        ));
    }

    let security_dir = files_dir.join(SECURITY_DIR);
    fs::create_dir_all(&security_dir)?;
    validate_security_dir(&security_dir)?;

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(pin, &salt)
        .map_err(crypto_error)?;

    let phc = Zeroizing::new(hash.to_string());
    let final_path = verifier_path(files_dir);
    let temporary_path = write_verifier_atomically(&security_dir, phc.as_bytes())?;

    if let Err(error) = fs::rename(&temporary_path, &final_path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }

    Ok(())
}

pub fn configured(files_dir: &Path) -> bool {
    if validate_files_dir(files_dir).is_err() {
        return false;
    }

    match fs::symlink_metadata(verifier_path(files_dir)) {
        Ok(metadata) => metadata.is_file() && !metadata.file_type().is_symlink(),
        Err(_) => false,
    }
}

/// Checks the entered PIN against the stored Argon2id verifier.
pub fn matches(files_dir: &Path, pin: &[u8]) -> io::Result<bool> {
    validate_files_dir(files_dir)?;

    let verifier = match read_verifier(files_dir)? {
        Some(value) => value,
        None => return Ok(false),
    };

    let parsed = PasswordHash::new(verifier.as_str()).map_err(crypto_error)?;

    Ok(Argon2::default().verify_password(pin, &parsed).is_ok())
}

/// Removes all SecureGSI VM instances from the application's private files
/// directory. This does NOT uninstall the application or touch files outside
/// the app sandbox.
///
/// This is filesystem deletion, not cryptographic erasure. Once VM storage is
/// moved behind an encrypted vault, the Duress flow should destroy the vault
/// master key first and use this deletion only as secondary cleanup.
pub fn wipe_instances(files_dir: &Path) -> io::Result<()> {
    validate_files_dir(files_dir)?;

    let instances = files_dir.join("instances");

    match fs::symlink_metadata(&instances) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            fs::remove_file(&instances)?;
        }
        Ok(metadata) if metadata.is_dir() => {
            fs::remove_dir_all(&instances)?;
        }
        Ok(_) => {
            fs::remove_file(&instances)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    // Only remove the verifier after instance deletion succeeded. If deletion
    // fails, the same Duress PIN can be used to retry.
    let verifier = verifier_path(files_dir);

    match fs::symlink_metadata(&verifier) {
        Ok(_) => fs::remove_file(verifier)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root() -> PathBuf {
        let mut random_id = [0_u8; 16];
        OsRng.fill_bytes(&mut random_id);

        let id = random_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("securegsi-tests");

        fs::create_dir_all(&base).expect("create test base");

        let root = base.join(format!("duress-{id}"));
        fs::create_dir(&root).expect("create unique test root");

        root
    }

    #[test]
    fn configure_match_and_wipe() {
        let root = test_root();
        let guest_data = root.join("instances/default/data");

        fs::create_dir_all(&guest_data).expect("create guest data");
        fs::write(guest_data.join("secret.txt"), b"SECRET-DURESS-TEST").expect("write marker");

        configure(&root, b"7391").expect("configure");
        assert!(configured(&root));
        assert!(!matches(&root, b"1111").expect("wrong pin check"));
        assert!(matches(&root, b"7391").expect("correct pin check"));

        wipe_instances(&root).expect("wipe");

        assert!(!root.join("instances").exists());
        assert!(!configured(&root));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn oversized_verifier_is_rejected() {
        let root = test_root();
        let security_dir = root.join(SECURITY_DIR);
        fs::create_dir_all(&security_dir).expect("create security dir");
        fs::write(
            verifier_path(&root),
            vec![b'X'; MAX_VERIFIER_BYTES as usize + 1],
        )
        .expect("write oversized verifier");

        assert!(matches(&root, b"7391").is_err());

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn instance_symlink_is_unlinked_not_followed() {
        use std::os::unix::fs::symlink;

        let root = test_root();
        let outside = test_root();
        let marker = outside.join("must-survive.txt");
        fs::write(&marker, b"KEEP").expect("write outside marker");

        symlink(&outside, root.join("instances")).expect("create instances symlink");

        wipe_instances(&root).expect("wipe");

        assert!(marker.exists());
        assert!(!root.join("instances").exists());

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }
}
