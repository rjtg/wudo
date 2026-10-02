//! One bounded worker owns SQLite. A started transaction outlives its requester.
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Instant,
};
use tokio::sync::{mpsc, oneshot};
use wudo_protocol::v2::Error;
use wudo_store::{Store, User};

pub(crate) enum Command {
    Initialize,
    Upgrade,
    Create(String, String),
    Inspect(String),
}
pub(crate) enum Reply {
    Ready,
    User(User),
}
struct Job {
    command: Command,
    deadline: Instant,
    reply: oneshot::Sender<Result<Reply, Error>>,
}
#[derive(Clone)]
pub(crate) struct Client {
    tx: mpsc::Sender<Job>,
}
pub(crate) struct Worker {
    client: Client,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}
impl Client {
    pub(crate) async fn request(
        &self,
        command: Command,
        deadline: Instant,
    ) -> Result<Reply, Error> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .try_send(Job {
                command,
                deadline,
                reply,
            })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => Error::Busy,
                _ => Error::Unavailable,
            })?;
        rx.await.map_err(|_| Error::Unavailable)?
    }
}
impl Worker {
    pub(crate) fn start(path: PathBuf, anchor: Option<std::os::fd::OwnedFd>) -> Result<Self, ()> {
        let (tx, mut rx) = mpsc::channel::<Job>(4);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let join = thread::Builder::new().name("wudo-storage".into()).spawn(move || {
            let anchor = anchor;
            if !same_directory(&path, anchor.as_ref()) { let _ = ready_tx.send(Err(())); return; }
            let mut store = match std::fs::symlink_metadata(path.join("identity.sqlite3")) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Orphan sidecars are not a fresh installation.
                    if ["-journal", "-wal", "-shm"].iter().any(|suffix| {
                        !matches!(std::fs::symlink_metadata(path.join(format!("identity.sqlite3{suffix}"))), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
                    }) { let _ = ready_tx.send(Err(())); return; }
                    None
                }
                Ok(_) => match Store::open_for_upgrade(&path) { Ok(s) => Some(s), Err(_) => { let _ = ready_tx.send(Err(())); return; } },
                Err(_) => { let _ = ready_tx.send(Err(())); return; }
            };
            let _ = ready_tx.send(Ok(()));
            let mut failed = false;
            while let Some(job) = rx.blocking_recv() {
                if stopping.load(Ordering::Acquire) { break; }
                if job.reply.is_closed() || Instant::now() >= job.deadline { continue; }
                let result = if failed || !same_directory(&path, anchor.as_ref()) {
                    failed = true; Err(Error::Unavailable) } else {
                    match job.command {
                        Command::Initialize if store.is_some() => Err(Error::Conflict),
                        Command::Initialize => match Store::initialize(&path) {
                            Ok(s) => { store = Some(s); Ok(Reply::Ready) },
                            Err(_) => { failed = true; Err(Error::InternalError) },
                        },
                        Command::Upgrade if store.is_none() => Err(Error::Unavailable),
                        Command::Upgrade => match Store::upgrade(&path) {
                            Ok(s) => { store = Some(s); Ok(Reply::Ready) },
                            Err(_) => { failed = true; Err(Error::InternalError) },
                        },
                        Command::Create(_, _) | Command::Inspect(_) if store.as_ref().is_some_and(|s| s.needs_upgrade().unwrap_or(true)) => Err(Error::Unavailable),
                        Command::Create(name, label) => match store.as_mut() {
                            Some(s) => s.create_user(&name, &label).map(Reply::User).map_err(map_error),
                            None => Err(Error::Unavailable),
                        },
                        Command::Inspect(name) => match store.as_ref() {
                            Some(s) => s.user_by_name(&name).map_err(map_error).and_then(|u| u.map(Reply::User).ok_or(Error::Unavailable)),
                            None => Err(Error::Unavailable),
                        },
                    }
                };
                if matches!(result, Err(Error::InternalError)) { failed = true; }
                let _ = job.reply.send(result);
            }
        }).map_err(|_| ())?;
        if ready_rx.recv().map_err(|_| ())?.is_err() {
            let _ = join.join();
            return Err(());
        }
        Ok(Self {
            client: Client { tx },
            stop,
            join: Some(join),
        })
    }
    pub(crate) fn client(&self) -> Client {
        self.client.clone()
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Wake an idle worker without waiting for queue space.
        let (reply, _) = oneshot::channel();
        let _ = self.client.tx.try_send(Job {
            command: Command::Inspect(String::new()),
            deadline: Instant::now(),
            reply,
        });
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}
fn map_error(error: wudo_store::Error) -> Error {
    match error {
        wudo_store::Error::InvalidInput => Error::InvalidRequest,
        wudo_store::Error::Conflict => Error::Conflict,
        wudo_store::Error::Capacity => Error::Unavailable,
        _ => Error::InternalError,
    }
}

pub(crate) fn production() -> Result<Worker, ()> {
    use rustix::fs::{self, Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut fd = fs::open("/", flags, Mode::empty()).map_err(|_| ())?;
    check_directory(&fd, false)?;
    for component in ["var", "lib", "wudo"] {
        fd = fs::openat(&fd, component, flags, Mode::empty()).map_err(|_| ())?;
        check_directory(&fd, component == "wudo")?;
    }
    // Stable directory inode lock: never lock a replaceable database inode.
    fs::flock(&fd, fs::FlockOperation::NonBlockingLockExclusive).map_err(|_| ())?;
    // SQLite NOFOLLOW rejects procfs descriptor aliases. All ancestors of this
    // fixed path were validated; root is trusted not to replace them.
    let path = PathBuf::from("/var/lib/wudo");
    Worker::start(path, Some(fd))
}
fn check_directory(fd: &std::os::fd::OwnedFd, leaf: bool) -> Result<(), ()> {
    use rustix::{fs, io::Errno};
    let stat = fs::fstat(fd).map_err(|_| ())?;
    if stat.st_uid != 0
        || stat.st_mode & 0o022 != 0
        || (leaf && (stat.st_gid != 0 || stat.st_mode & 0o7777 != 0o700))
    {
        return Err(());
    }
    for key in ["system.posix_acl_access", "system.posix_acl_default"] {
        if !matches!(fs::fgetxattr(fd, key, &mut [0u8; 0]), Err(Errno::NODATA)) {
            return Err(());
        }
    }
    Ok(())
}

fn same_directory(path: &std::path::Path, anchor: Option<&std::os::fd::OwnedFd>) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(fd) = anchor else {
        return true;
    };
    match (std::fs::symlink_metadata(path), rustix::fs::fstat(fd)) {
        (Ok(m), Ok(s)) => m.is_dir() && m.dev() == s.st_dev && m.ino() == s.st_ino,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }
    #[test]
    fn descriptor_path_init_upgrade_restart_and_invalid_state() {
        let d = dir();
        let fd = rustix::fs::open(
            d.path(),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let path = d.path().to_path_buf();
        let worker = Worker::start(path, Some(fd)).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let c = worker.client();
            let deadline = || Instant::now() + std::time::Duration::from_secs(5);
            assert!(matches!(
                c.request(Command::Upgrade, deadline()).await,
                Err(Error::Unavailable)
            ));
            assert!(matches!(
                c.request(Command::Initialize, deadline()).await,
                Ok(Reply::Ready)
            ));
            assert!(matches!(
                c.request(Command::Initialize, deadline()).await,
                Err(Error::Conflict)
            ));
            assert!(matches!(
                c.request(Command::Create("alice".into(), "Alice".into()), deadline())
                    .await,
                Ok(Reply::User(_))
            ));
            assert!(matches!(
                c.request(Command::Upgrade, deadline()).await,
                Ok(Reply::Ready)
            ));
        });
        drop(worker);
        let worker = Worker::start(d.path().into(), None).unwrap();
        rt.block_on(async {
            assert!(matches!(
                worker
                    .client()
                    .request(
                        Command::Inspect("alice".into()),
                        Instant::now() + std::time::Duration::from_secs(5)
                    )
                    .await,
                Ok(Reply::User(_))
            ));
        });
        drop(worker);
        std::fs::write(d.path().join("identity.sqlite3"), b"corrupt").unwrap();
        assert!(Worker::start(d.path().into(), None).is_err());
    }
    #[test]
    fn expired_and_cancelled_jobs_never_write_and_queue_is_bounded() {
        let d = dir();
        let worker = Worker::start(d.path().into(), None).unwrap();
        let (reply, rx) = oneshot::channel();
        worker
            .client
            .tx
            .try_send(Job {
                command: Command::Initialize,
                deadline: Instant::now(),
                reply,
            })
            .unwrap_or_else(|_| panic!("queue"));
        assert!(rx.blocking_recv().is_err());
        assert!(!d.path().join("identity.sqlite3").exists());
        let (reply, receiver) = oneshot::channel();
        drop(receiver);
        worker
            .client
            .tx
            .try_send(Job {
                command: Command::Initialize,
                deadline: Instant::now() + std::time::Duration::from_secs(5),
                reply,
            })
            .unwrap_or_else(|_| panic!("queue"));
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        // The FIFO inspection is a barrier proving the cancelled initialize was skipped.
        assert!(matches!(
            rt.block_on(worker.client().request(
                Command::Inspect("alice".into()),
                Instant::now() + std::time::Duration::from_secs(5)
            )),
            Err(Error::Unavailable)
        ));
        assert!(!d.path().join("identity.sqlite3").exists());
        drop(worker);
        // Deterministic admission capacity, without racing the consumer.
        let (tx, mut rx) = mpsc::channel(4);
        for _ in 0..4 {
            let (reply, receiver) = oneshot::channel();
            drop(receiver);
            tx.try_send(Job {
                command: Command::Initialize,
                deadline: Instant::now(),
                reply,
            })
            .unwrap_or_else(|_| panic!("queue"));
        }
        let client = Client { tx };
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert!(matches!(
            rt.block_on(client.request(Command::Initialize, Instant::now())),
            Err(Error::Busy)
        ));
        while let Ok(job) = rx.try_recv() {
            assert!(job.reply.is_closed());
        }
    }
}
