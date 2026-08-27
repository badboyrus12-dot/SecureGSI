use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use rand_core::OsRng;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const SECURITY_DIR: &str = "security";
const VERIFIER_FILE: &str = "duress.phc";

fn verifier_path(files_dir: &Path) -> PathBuf {
    files_dir.join(SECURITY_DIR).join(VERIFIER_FILE)
}

fn crypto_error(message: impl ToString) -> io::Error {
    io::Error::other(message.to_string())
}

fn validate_files_dir(files_dir: &Path) -> io::Result<()> {
    if files_dir.as_os_str().is_empty() || files_dir == Path::new("/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsafe filesDir",
        ));
    }

    Ok(())
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

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(pin, &salt)
        .map_err(crypto_error)?;

    let phc = Zeroizing::new(hash.to_string());
    let final_path = verifier_path(files_dir);
    let temporary_path = security_dir.join("duress.phc.tmp");

    fs::write(&temporary_path, phc.as_bytes())?;

    if let Err(error) = fs::rename(&temporary_path, &final_path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }

    Ok(())
}

pub fn configured(files_dir: &Path) -> bool {
    verifier_path(files_dir).is_file()
}

/// Checks the entered PIN against the stored Argon2id verifier.
pub fn matches(files_dir: &Path, pin: &[u8]) -> io::Result<bool> {
    validate_files_dir(files_dir)?;

    let verifier = match fs::read_to_string(verifier_path(files_dir)) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };

    let verifier = Zeroizing::new(verifier);
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

    if instances.exists() {
        fs::remove_dir_all(&instances)?;
    }

    // Only remove the verifier after instance deletion succeeded. If deletion
    // fails, the same Duress PIN can be used to retry.
    let verifier = verifier_path(files_dir);
    if verifier.exists() {
        fs::remove_file(verifier)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;
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
}
