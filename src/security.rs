//! Reusable, hardened filesystem primitives.
//!
//! These helpers are the trusted core of a security product: every byte written
//! to disk and every file the daemon decides to trust flows through here. They
//! are intentionally small, dependency-light, and exhaustively tested.
//!
//! Guarantees provided:
//!
//! * **Atomic replacement** — [`secure_write`] writes to a temporary file in the
//!   destination directory, `fsync`s it, then atomically renames it into place
//!   and `fsync`s the directory. Readers never observe a partial file, even
//!   across a crash.
//! * **No symlink traversal of the target name** — `rename` replaces the target
//!   name itself rather than following it, and [`ensure_not_symlink`] lets
//!   callers reject symlinks explicitly before trusting a path.
//! * **Permission and ownership validation** — helpers verify that managed files
//!   are owned by the expected user and are not writable by group/other.
//!
//! All metadata inspection uses `lstat` semantics ([`std::fs::symlink_metadata`])
//! so a final-component symlink is detected rather than followed.
//!
//! On error these helpers log the offending path via structured `tracing` and
//! return a path-free [`Error`], per the crate's no-path-leakage policy.

use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use crate::errors::{Error, Result};

/// Permission bits for files that may contain secrets (owner read/write only).
pub const MODE_SECRET: u32 = 0o600;

/// Permission bits for non-secret managed files (owner write, others read).
pub const MODE_PUBLIC: u32 = 0o644;

/// Permission bits for managed directories (owner only).
pub const MODE_DIR: u32 = 0o700;

/// Permission mask for "writable by group or other".
const GROUP_OR_OTHER_WRITABLE: u32 = 0o022;

/// Atomically write `contents` to `path` with permission bits `mode`.
///
/// The data is written to a uniquely-named temporary file in the *same*
/// directory as `path` (so the final rename is atomic on POSIX filesystems),
/// the permission bits are applied to that temporary file *before* it is moved
/// into place (so contents are never briefly exposed under laxer permissions),
/// the file is `fsync`ed, and finally it is atomically renamed over `path` with
/// a directory `fsync` to make the rename durable.
///
/// # Errors
///
/// Returns [`Error::InvalidPath`] if `path` has no parent directory, or
/// [`Error::Io`] if any filesystem step fails.
pub fn secure_write(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let parent = parent_of(path)?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(|e| io(path, e))?;

    tmp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|e| io(path, e))?;

    tmp.write_all(contents).map_err(|e| io(path, e))?;
    tmp.as_file().sync_all().map_err(|e| io(path, e))?;

    // Disarm automatic deletion and take ownership of the temp path so we can
    // perform the atomic rename ourselves (and reuse `atomic_replace`).
    let (_file, tmp_path) = tmp.keep().map_err(|e| io(path, e.error))?;

    atomic_replace(&tmp_path, path)
}

/// Atomically replace `dst` with `src` via `rename`, then `fsync` the
/// destination directory so the rename survives a crash.
///
/// `src` and `dst` must reside on the same filesystem (the common case, since
/// `src` is normally a temporary file created in `dst`'s directory).
///
/// # Errors
///
/// Returns [`Error::InvalidPath`] if `dst` has no parent directory, or
/// [`Error::Io`] if the rename or directory `fsync` fails.
pub fn atomic_replace(src: &Path, dst: &Path) -> Result<()> {
    let parent = parent_of(dst)?;
    std::fs::rename(src, dst).map_err(|e| io(dst, e))?;
    fsync_dir(parent)
}

/// `fsync` a directory so a contained create/rename becomes durable.
///
/// # Errors
///
/// Returns [`Error::Io`] if the directory cannot be opened or synced.
pub fn fsync_dir(dir: &Path) -> Result<()> {
    let handle = std::fs::File::open(dir).map_err(|e| io(dir, e))?;
    handle.sync_all().map_err(|e| io(dir, e))
}

/// Return whether `path` is a symbolic link (without following it).
///
/// A non-existent path is reported as `false`.
///
/// # Errors
///
/// Returns [`Error::Io`] for filesystem errors other than "not found".
pub fn is_symlink(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => Ok(meta.file_type().is_symlink()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io(path, e)),
    }
}

/// Reject `path` if it is a symbolic link.
///
/// # Errors
///
/// Returns [`Error::UnexpectedSymlink`] if `path` is a symlink, or
/// [`Error::Io`] for other filesystem errors.
pub fn ensure_not_symlink(path: &Path) -> Result<()> {
    if is_symlink(path)? {
        tracing::warn!(path = %path.display(), "rejected symlink for managed path");
        return Err(Error::UnexpectedSymlink);
    }
    Ok(())
}

/// Validate that `path` is owned by `expected_uid` (using `lstat` semantics).
///
/// # Errors
///
/// Returns [`Error::InsecureOwnership`] if the owner differs, or [`Error::Io`]
/// if metadata cannot be read.
pub fn validate_owner(path: &Path, expected_uid: u32) -> Result<()> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| io(path, e))?;
    if meta.uid() != expected_uid {
        tracing::warn!(
            path = %path.display(),
            owner_uid = meta.uid(),
            expected_uid,
            "rejected path with unexpected owner"
        );
        return Err(Error::InsecureOwnership);
    }
    Ok(())
}

/// Validate that `path` is not writable by group or other.
///
/// # Errors
///
/// Returns [`Error::InsecurePermissions`] if any group/other write bit is set,
/// or [`Error::Io`] if metadata cannot be read.
pub fn ensure_not_group_or_world_writable(path: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| io(path, e))?;
    let mode = meta.mode() & 0o777;
    if mode & GROUP_OR_OTHER_WRITABLE != 0 {
        tracing::warn!(
            path = %path.display(),
            mode = format!("{mode:#o}"),
            "rejected path with group/other-writable permissions"
        );
        return Err(Error::InsecurePermissions);
    }
    Ok(())
}

/// Validate that `path`'s permission bits do not exceed `allowed_mode`.
///
/// Any permission bit set on the file but absent from `allowed_mode` is treated
/// as insecure. For example, `validate_mode_at_most(p, 0o644)` rejects a file
/// that is group- or world-writable, or executable.
///
/// # Errors
///
/// Returns [`Error::InsecurePermissions`] if extra bits are present, or
/// [`Error::Io`] if metadata cannot be read.
pub fn validate_mode_at_most(path: &Path, allowed_mode: u32) -> Result<()> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| io(path, e))?;
    let mode = meta.mode() & 0o777;
    if mode & !(allowed_mode & 0o777) != 0 {
        tracing::warn!(
            path = %path.display(),
            mode = format!("{mode:#o}"),
            allowed = format!("{:#o}", allowed_mode & 0o777),
            "rejected path with excessive permissions"
        );
        return Err(Error::InsecurePermissions);
    }
    Ok(())
}

/// Return the parent directory of `path`, or [`Error::InvalidPath`].
fn parent_of(path: &Path) -> Result<&Path> {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            tracing::warn!(path = %path.display(), "path has no parent directory");
            Error::InvalidPath
        })
}

/// Map an [`std::io::Error`] to [`Error::Io`], logging the offending path.
fn io(path: &Path, source: std::io::Error) -> Error {
    tracing::warn!(path = %path.display(), error = %source, "filesystem operation failed");
    Error::Io(source)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("create tempdir")
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path).unwrap().mode() & 0o777
    }

    #[test]
    fn secure_write_creates_file_with_contents_and_mode() {
        let dir = tempdir();
        let path = dir.path().join("file");
        secure_write(&path, b"hello", MODE_SECRET).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
        assert_eq!(mode_of(&path), MODE_SECRET);
    }

    #[test]
    fn secure_write_replaces_existing_file_atomically() {
        let dir = tempdir();
        let path = dir.path().join("file");
        secure_write(&path, b"v1", MODE_PUBLIC).unwrap();
        secure_write(&path, b"v2-longer", MODE_PUBLIC).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"v2-longer");

        // No leftover temporary files in the directory.
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("file")]);
    }

    #[test]
    fn secure_write_rejects_pathless_parent() {
        // A bare relative file name has a parent of "" which we treat as invalid.
        let err = secure_write(Path::new("bare"), b"x", MODE_PUBLIC).unwrap_err();
        assert!(matches!(err, Error::InvalidPath));
    }

    #[test]
    fn atomic_replace_moves_file_and_is_durable() {
        let dir = tempdir();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        std::fs::write(&src, b"payload").unwrap();
        atomic_replace(&src, &dst).unwrap();
        assert!(!src.exists());
        assert_eq!(std::fs::read(&dst).unwrap(), b"payload");
    }

    #[test]
    fn fsync_dir_succeeds() {
        let dir = tempdir();
        let path = dir.path().join("file");
        std::fs::write(&path, b"data").unwrap();
        fsync_dir(dir.path()).unwrap();
    }

    #[test]
    fn is_symlink_detects_links_and_handles_missing() {
        let dir = tempdir();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        let missing = dir.path().join("missing");
        std::fs::write(&target, b"t").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(!is_symlink(&target).unwrap());
        assert!(is_symlink(&link).unwrap());
        assert!(!is_symlink(&missing).unwrap());
    }

    #[test]
    fn ensure_not_symlink_rejects_links() {
        let dir = tempdir();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        std::fs::write(&target, b"t").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        ensure_not_symlink(&target).unwrap();
        assert!(matches!(
            ensure_not_symlink(&link).unwrap_err(),
            Error::UnexpectedSymlink
        ));
    }

    #[test]
    fn validate_owner_accepts_current_owner() {
        let dir = tempdir();
        let path = dir.path().join("file");
        std::fs::write(&path, b"x").unwrap();
        let uid = std::fs::symlink_metadata(&path).unwrap().uid();
        validate_owner(&path, uid).unwrap();
    }

    #[test]
    fn validate_owner_rejects_wrong_owner() {
        let dir = tempdir();
        let path = dir.path().join("file");
        std::fs::write(&path, b"x").unwrap();
        let uid = std::fs::symlink_metadata(&path).unwrap().uid();
        // Pick a uid that is definitely not the owner.
        let wrong = uid.wrapping_add(1);
        assert!(matches!(
            validate_owner(&path, wrong).unwrap_err(),
            Error::InsecureOwnership
        ));
    }

    #[test]
    fn ensure_not_group_or_world_writable_enforced() {
        let dir = tempdir();
        let path = dir.path().join("file");
        std::fs::write(&path, b"x").unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        ensure_not_group_or_world_writable(&path).unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o646)).unwrap();
        assert!(matches!(
            ensure_not_group_or_world_writable(&path).unwrap_err(),
            Error::InsecurePermissions
        ));

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o620)).unwrap();
        assert!(matches!(
            ensure_not_group_or_world_writable(&path).unwrap_err(),
            Error::InsecurePermissions
        ));
    }

    #[test]
    fn validate_mode_at_most_enforced() {
        let dir = tempdir();
        let path = dir.path().join("file");
        std::fs::write(&path, b"x").unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        validate_mode_at_most(&path, 0o644).unwrap();
        validate_mode_at_most(&path, 0o600).unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            validate_mode_at_most(&path, 0o644).unwrap_err(),
            Error::InsecurePermissions
        ));
    }
}
