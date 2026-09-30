//! Linux-only socket lifecycle in an administrator-controlled directory.
use rustix::{
    fs::{self, AtFlags, FileType, Mode, OFlags, Stat},
    io::Errno,
    net::{self, AddressFamily, SocketAddrUnix, SocketFlags, SocketType},
    process::Gid,
};
use std::{
    os::fd::{AsRawFd, OwnedFd},
    os::unix::net::UnixListener,
    sync::Arc,
};

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

pub(crate) struct Directory {
    fd: OwnedFd,
}
pub(crate) struct Endpoint {
    dir: Arc<Directory>,
    name: &'static str,
    identity: Stat,
}
impl Directory {
    pub(crate) fn production() -> Result<Arc<Self>, ()> {
        let mut fd = fs::open("/", DIR_FLAGS, Mode::empty()).map_err(|_| ())?;
        check_directory(&fd, 0, false)?;
        for component in ["run", "wudo"] {
            fd = fs::openat(&fd, component, DIR_FLAGS, Mode::empty()).map_err(|_| ())?;
            check_directory(&fd, 0, component == "wudo")?;
        }
        Ok(Arc::new(Self { fd }))
    }
    fn path(&self, name: &str) -> String {
        format!("/proc/self/fd/{}/{name}", self.fd.as_raw_fd())
    }
    pub(crate) fn absent(&self, name: &str) -> Result<(), ()> {
        match fs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => Ok(()),
            _ => Err(()),
        }
    }
    pub(crate) fn bind(
        self: &Arc<Self>,
        name: &'static str,
        gid: Gid,
        mode: Mode,
    ) -> Result<(UnixListener, Endpoint), ()> {
        self.absent(name)?;
        let socket = net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .map_err(|_| ())?;
        let path = self.path(name);
        let addr = SocketAddrUnix::new(path.as_str()).map_err(|_| ())?;
        net::bind(&socket, &addr).map_err(|_| ())?;
        // The parent is descriptor-anchored and not writable by untrusted users.
        // Root is trusted not to replace an entry between bind and this snapshot.
        let identity = fs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| ())?;
        let endpoint = Endpoint {
            dir: Arc::clone(self),
            name,
            identity,
        };
        endpoint.matches()?;
        fs::chownat(&self.fd, name, None, Some(gid), AtFlags::SYMLINK_NOFOLLOW).map_err(|_| ())?;
        fs::chmodat(&self.fd, name, mode, AtFlags::empty()).map_err(|_| ())?;
        // O_PATH can open a socket inode without connecting to the socket.
        let inode = fs::openat(
            &self.fd,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ())?;
        let actual = fs::fstat(&inode).map_err(|_| ())?;
        if !same_socket(&actual, &identity)
            || actual.st_uid != identity.st_uid
            || actual.st_gid != gid.as_raw()
            || actual.st_mode & 0o7777 != mode.bits()
        {
            return Err(());
        }
        // Linux O_PATH descriptors cannot use fgetxattr. Resolve the verified
        // inode via procfs, rather than re-opening the original endpoint path.
        let inode_path = format!("/proc/self/fd/{}", inode.as_raw_fd());
        no_acl_result(fs::getxattr(
            inode_path.as_str(),
            "system.posix_acl_access",
            &mut [0u8; 0],
        ))?;
        endpoint.matches()?;
        net::listen(&socket, 16).map_err(|_| ())?;
        Ok((UnixListener::from(socket), endpoint))
    }
}
fn no_acl_result(result: Result<usize, Errno>) -> Result<(), ()> {
    match result {
        Err(Errno::NODATA) => Ok(()),
        _ => Err(()),
    }
}
fn check_directory(fd: &OwnedFd, owner: u32, runtime: bool) -> Result<(), ()> {
    let stat = fs::fstat(fd).map_err(|_| ())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != owner
        || stat.st_mode & 0o022 != 0
        || (runtime && stat.st_mode & 0o7777 != 0o755)
    {
        return Err(());
    }
    no_acl_result(fs::fgetxattr(fd, "system.posix_acl_access", &mut [0u8; 0]))?;
    if runtime {
        no_acl_result(fs::fgetxattr(fd, "system.posix_acl_default", &mut [0u8; 0]))?;
    }
    Ok(())
}
fn same_socket(a: &Stat, b: &Stat) -> bool {
    FileType::from_raw_mode(a.st_mode) == FileType::Socket
        && a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
}
impl Endpoint {
    fn matches(&self) -> Result<(), ()> {
        let current =
            fs::statat(&self.dir.fd, self.name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| ())?;
        if same_socket(&current, &self.identity) {
            Ok(())
        } else {
            Err(())
        }
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        if self.matches().is_err()
            || fs::unlinkat(&self.dir.fd, self.name, AtFlags::empty()).is_err()
        {
            eprintln!("wudod: socket-cleanup-failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static N: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "wudod-socket-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            Self(path)
        }
        fn dir(&self) -> Arc<Directory> {
            let fd = fs::open(&self.0, DIR_FLAGS, Mode::empty()).unwrap();
            check_directory(&fd, rustix::process::geteuid().as_raw(), true).unwrap();
            Arc::new(Directory { fd })
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn permissions_cleanup_and_existing_entries() {
        let temp = Temp::new();
        let dir = temp.dir();
        let (listener, endpoint) = dir
            .bind(
                "test.sock",
                rustix::process::getegid(),
                Mode::from_raw_mode(0o600),
            )
            .unwrap();
        assert_eq!(
            std::fs::symlink_metadata(temp.0.join("test.sock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(dir.absent("test.sock").is_err());
        assert!(
            dir.bind("test.sock", rustix::process::getegid(), Mode::RUSR)
                .is_err()
        );
        drop(listener);
        drop(endpoint);
        assert!(!temp.0.join("test.sock").exists());
        std::fs::write(temp.0.join("file"), b"keep").unwrap();
        assert!(dir.absent("file").is_err());
        symlink("missing", temp.0.join("link")).unwrap();
        assert!(dir.absent("link").is_err());
    }
    #[test]
    fn cleanup_preserves_replacements_and_partial_setup_rolls_back() {
        let temp = Temp::new();
        let dir = temp.dir();
        let (listener, endpoint) = dir
            .bind(
                "first.sock",
                rustix::process::getegid(),
                Mode::from_raw_mode(0o600),
            )
            .unwrap();
        std::fs::remove_file(temp.0.join("first.sock")).unwrap();
        std::fs::write(temp.0.join("first.sock"), b"replacement").unwrap();
        drop(listener);
        drop(endpoint);
        assert_eq!(
            std::fs::read(temp.0.join("first.sock")).unwrap(),
            b"replacement"
        );
        let result: Result<(), ()> = (|| {
            let (_listener, _guard) = dir.bind(
                "second.sock",
                rustix::process::getegid(),
                Mode::from_raw_mode(0o600),
            )?;
            dir.bind("first.sock", rustix::process::getegid(), Mode::RUSR)?;
            Ok(())
        })();
        assert!(result.is_err());
        assert!(!temp.0.join("second.sock").exists());
    }
    #[test]
    fn rejects_unsafe_directory_and_symlinks() {
        let temp = Temp::new();
        let dir = temp.dir();
        assert!(check_directory(&dir.fd, rustix::process::geteuid().as_raw() ^ 1, true).is_err());
        std::fs::set_permissions(&temp.0, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(check_directory(&dir.fd, rustix::process::geteuid().as_raw(), true).is_err());
        symlink(&temp.0, temp.0.join("link")).unwrap();
        assert!(fs::openat(&dir.fd, "link", DIR_FLAGS, Mode::empty()).is_err());
        assert!(no_acl_result(Ok(0)).is_err());
        assert!(no_acl_result(Err(Errno::NOTSUP)).is_err());
    }
}
