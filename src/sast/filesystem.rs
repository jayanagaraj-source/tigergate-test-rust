//! Filesystem fixtures: CWE-22, CWE-73, CWE-377, CWE-732, CWE-59.

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const UPLOAD_ROOT: &str = "/var/app/uploads";

/// SAST: CWE-22 path traversal (`../../etc/passwd`) via string formatting.
pub fn read_upload(filename: &str) -> std::io::Result<String> {
    let path = format!("{}/{}", UPLOAD_ROOT, filename);
    fs::read_to_string(path)
}

/// SAST: CWE-22 path traversal via Path::join (absolute input replaces the base).
pub fn delete_attachment(user_path: &str) -> std::io::Result<()> {
    fs::remove_file(Path::new(UPLOAD_ROOT).join(user_path))
}

/// SAST: CWE-73 external control of file name for a write.
pub fn save_avatar(filename: &str, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(PathBuf::from(UPLOAD_ROOT).join(filename), bytes)
}

/// SAST: CWE-22 "zip slip" — tar entries unpacked to attacker-chosen paths
/// (also reaches tar 0.4.35, RUSTSEC-2021-0080).
pub fn extract_archive(archive_bytes: &[u8], dest: &Path) -> std::io::Result<()> {
    let mut archive = tar::Archive::new(archive_bytes);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_path = entry.path()?.into_owned();
        entry.unpack(dest.join(entry_path))?;
    }
    Ok(())
}

/// SAST: CWE-377 insecure temporary file with a predictable name in a shared dir,
/// plus CWE-732 world-writable permissions.
pub fn write_session_cache(data: &str) -> std::io::Result<PathBuf> {
    let path = std::env::temp_dir().join("tigergate-session.cache");
    fs::write(&path, data)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o777))?;
    Ok(path)
}

/// SAST: CWE-732 world-writable directory holding secrets.
pub fn create_key_dir(dir: &str) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o777))
}

/// SAST: CWE-59 / CWE-367 TOCTOU check-then-use on a user-supplied path (symlink race).
pub fn read_if_not_symlink(user_path: &str) -> std::io::Result<String> {
    let meta = fs::symlink_metadata(user_path)?;
    if meta.file_type().is_symlink() {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "symlink"));
    }
    let mut contents = String::new();
    fs::File::open(user_path)?.read_to_string(&mut contents)?;
    Ok(contents)
}
