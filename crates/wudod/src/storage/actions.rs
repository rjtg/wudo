//! Fixed privileged startup path. No client-selected path or live reload.
use rustix::{
    fs::{self, Mode, OFlags},
    io::Errno,
};
use std::{
    fs::File,
    io::Read,
    os::fd::{AsFd, OwnedFd},
};
use wudo_core::config::{Config, MAX_INPUT_BYTES};
const DIR: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
fn no_acl(fd: impl AsFd) -> Result<(), ()> {
    for name in ["system.posix_acl_access", "system.posix_acl_default"] {
        if !matches!(fs::fgetxattr(&fd, name, &mut [0; 0]), Err(Errno::NODATA)) {
            return Err(());
        }
    }
    Ok(())
}
fn directory(fd: &OwnedFd, leaf: bool, uid: u32) -> Result<(), ()> {
    let s = fs::fstat(fd).map_err(|_| ())?;
    if s.st_uid != uid
        || s.st_mode & 0o022 != 0
        || (leaf && (s.st_gid != uid || s.st_mode & 0o7777 != 0o755))
    {
        return Err(());
    }
    no_acl(fd)
}
pub(super) fn production() -> Result<(Config, wudo_core::settings::Settings), ()> {
    let root = fs::open("/", DIR, Mode::empty()).map_err(|_| ())?;
    directory(&root, false, 0)?;
    let etc = fs::openat(&root, "etc", DIR, Mode::empty()).map_err(|_| ())?;
    directory(&etc, false, 0)?;
    let config = load(&etc, 0)?;
    if !config.actions().is_empty() && config.schema_version() != 2 {
        eprintln!(
            "wudod: actions-schema-upgrade-required (use schema_version=2; remove timeout_seconds/output_limit_bytes from systemd actions)"
        );
        return Err(());
    }
    let settings = match read(&etc, 0, "wudod.toml", 4096)? {
        Some(bytes) => wudo_core::settings::Settings::parse(&bytes).map_err(|_| ())?,
        None => wudo_core::settings::Settings::default(),
    };
    Ok((config, settings))
}
fn load(etc: &OwnedFd, uid: u32) -> Result<Config, ()> {
    match read(etc, uid, "actions.toml", MAX_INPUT_BYTES)? {
        Some(bytes) => Config::parse(&bytes).map_err(|_| ()),
        None => Ok(Config::empty()),
    }
}
fn read(etc: &OwnedFd, uid: u32, filename: &str, limit: usize) -> Result<Option<Vec<u8>>, ()> {
    let dir = match fs::openat(etc, "wudo", DIR, Mode::empty()) {
        Ok(v) => v,
        Err(Errno::NOENT) => return Ok(None),
        Err(_) => return Err(()),
    };
    directory(&dir, true, uid)?;
    let fd = match fs::openat(
        &dir,
        filename,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(v) => v,
        Err(Errno::NOENT) => return Ok(None),
        Err(_) => return Err(()),
    };
    let before = fs::fstat(&fd).map_err(|_| ())?;
    if before.st_uid != uid
        || before.st_gid != uid
        || ![0o600, 0o644].contains(&(before.st_mode & 0o7777))
        || before.st_nlink != 1
        || fs::FileType::from_raw_mode(before.st_mode) != fs::FileType::RegularFile
        || before.st_size < 0
        || before.st_size as u64 > limit as u64
    {
        return Err(());
    }
    no_acl(&fd)?;
    let mut file = File::from(fd);
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    let after = fs::fstat(&file).map_err(|_| ())?;
    let path = fs::statat(&dir, filename, fs::AtFlags::SYMLINK_NOFOLLOW).map_err(|_| ())?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mtime != after.st_mtime
        || before.st_mtime_nsec != after.st_mtime_nsec
        || before.st_ctime != after.st_ctime
        || before.st_ctime_nsec != after.st_ctime_nsec
        || before.st_mode != after.st_mode
        || before.st_uid != after.st_uid
        || before.st_gid != after.st_gid
        || before.st_nlink != after.st_nlink
        || path.st_dev != after.st_dev
        || path.st_ino != after.st_ino
    {
        return Err(());
    }
    if bytes.len() > limit {
        return Err(());
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn missing_safe_and_hostile_startup_files() {
        let tmp = tempfile::tempdir().unwrap();
        let etc = fs::open(tmp.path(), DIR, Mode::empty()).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        assert!(load(&etc, uid).unwrap().actions().is_empty());
        let dir = tmp.path().join("wudo");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(load(&etc, uid).unwrap().actions().is_empty());
        let file = dir.join("actions.toml");
        let valid = b"schema_version=1\n[resources]\n[actions]\n";
        std::fs::write(&file, valid).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&etc, uid).is_ok());
        assert!(load(&etc, uid + 1).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(load(&etc, uid).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(&etc, uid).is_ok());
        std::fs::hard_link(&file, dir.join("link")).unwrap();
        assert!(load(&etc, uid).is_err());
        std::fs::remove_file(dir.join("link")).unwrap();
        std::fs::write(&file, vec![b' '; MAX_INPUT_BYTES + 1]).unwrap();
        assert!(load(&etc, uid).is_err());
        std::fs::write(&file, b"invalid").unwrap();
        assert!(load(&etc, uid).is_err());
        std::fs::remove_file(&file).unwrap();
        symlink("missing", &file).unwrap();
        assert!(load(&etc, uid).is_err());
        std::fs::remove_file(&file).unwrap();
        fs::mknodat(
            dir_fd(&dir),
            "actions.toml",
            fs::FileType::Fifo,
            Mode::RUSR | Mode::WUSR,
            0,
        )
        .unwrap();
        assert!(load(&etc, uid).is_err());
        std::fs::remove_file(&file).unwrap();
        std::fs::write(&file, valid).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(load(&etc, uid).is_err());
    }
    #[test]
    fn rejects_directory_symlinks_and_access_or_default_acls() {
        let tmp = tempfile::tempdir().unwrap();
        let etc = dir_fd(tmp.path());
        let uid = rustix::process::geteuid().as_raw();
        let dir = tmp.path().join("wudo");
        symlink("missing", &dir).unwrap();
        assert!(load(&etc, uid).is_err());
        std::fs::remove_file(&dir).unwrap();
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let fd = dir_fd(&dir);
        // Linux POSIX ACL xattr v2: owner, named user, group, mask, other.
        // Keep mode 0755 so the ACL check, rather than mode validation, rejects it.
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in [
            (1u16, 7u16, u32::MAX),
            (2, 4, uid + 1),
            (4, 5, u32::MAX),
            (16, 5, u32::MAX),
            (32, 5, u32::MAX),
        ] {
            acl.extend(tag.to_le_bytes());
            acl.extend(perm.to_le_bytes());
            acl.extend(id.to_le_bytes());
        }
        for name in ["system.posix_acl_access", "system.posix_acl_default"] {
            fs::fsetxattr(&fd, name, &acl, fs::XattrFlags::empty()).unwrap();
            assert!(load(&etc, uid).is_err());
            fs::fremovexattr(&fd, name).unwrap();
            assert!(load(&etc, uid).is_ok());
        }
        let file = dir.join("actions.toml");
        std::fs::write(&file, b"schema_version=1\n[resources]\n[actions]\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let fd = fs::open(&file, OFlags::RDONLY, Mode::empty()).unwrap();
        // Match file mode 0644 while retaining a named ACL entry.
        acl[6..8].copy_from_slice(&6u16.to_le_bytes());
        acl[22..24].copy_from_slice(&4u16.to_le_bytes());
        acl[30..32].copy_from_slice(&4u16.to_le_bytes());
        acl[38..40].copy_from_slice(&4u16.to_le_bytes());
        fs::fsetxattr(
            &fd,
            "system.posix_acl_access",
            &acl,
            fs::XattrFlags::empty(),
        )
        .unwrap();
        assert!(load(&etc, uid).is_err());
    }
    fn dir_fd(path: &std::path::Path) -> OwnedFd {
        fs::open(path, DIR, Mode::empty()).unwrap()
    }
}
