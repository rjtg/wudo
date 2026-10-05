//! One bounded worker owns SQLite. A started transaction outlives its requester.
mod administration;
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
use wudo_protocol::v2::{self as wire, Error};
use wudo_store::{Store, User};
use wudod::enrollment::{Enrollment, Verified};

pub(crate) enum Command {
    Initialize,
    Administration(Vec<u8>),
    Configure(String),
    Reset(String),
    Enrollment(wire::Endpoint, Vec<u8>),
    Completed(Box<Verified>, Vec<u8>),
    Upgrade,
    Create(String, String),
    Inspect(String),
}
pub(crate) enum Reply {
    Ready,
    User(User),
    Encoded(Vec<u8>),
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
#[cfg(test)]
struct VerificationGate {
    started: oneshot::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}
pub(crate) struct Worker {
    #[cfg(test)]
    gate: Arc<std::sync::Mutex<Option<VerificationGate>>>,
    client: Client,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}
impl Client {
    pub(crate) async fn enrollment(
        &self,
        endpoint: wire::Endpoint,
        bytes: Vec<u8>,
        deadline: Instant,
    ) -> Result<Reply, Error> {
        let (reply, rx) = oneshot::channel();
        // Wait for the state owner, bounded by socket admission and the exchange
        // timeout. Only crypto admission may return Busy after consuming finish.
        self.tx
            .send(Job {
                command: Command::Enrollment(endpoint, bytes),
                deadline,
                reply,
            })
            .await
            .map_err(|_| Error::Unavailable)?;
        rx.await.map_err(|_| Error::Unavailable)?
    }

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
        #[cfg(test)]
        let gate = Arc::new(std::sync::Mutex::new(None::<VerificationGate>));
        #[cfg(test)]
        let thread_gate = gate.clone();
        let completion_tx = tx.downgrade();
        let join = thread::Builder::new()
            .name("wudo-storage".into())
            .spawn(move || {
                if !same_directory(&path, anchor.as_ref()) {
                    let _ = ready_tx.send(Err(()));
                    return;
                }
                let mut store = match open_store(&path) {
                    Ok(s) => s,
                    Err(()) => {
                        let _ = ready_tx.send(Err(()));
                        return;
                    }
                };
                let mut enrollment = None;
                let mut crypto: Vec<thread::JoinHandle<()>> = Vec::new();
                let _ = ready_tx.send(Ok(()));
                let mut failed = false;
                while let Some(job) = rx.blocking_recv() {
                    if stopping.load(Ordering::Acquire) {
                        break;
                    }
                    let mut i = 0;
                    while i < crypto.len() {
                        if crypto[i].is_finished() {
                            if crypto.swap_remove(i).join().is_err() {
                                failed = true;
                            }
                        } else {
                            i += 1;
                        }
                    }
                    let completion = matches!(&job.command, Command::Completed(..));
                    if !completion && (job.reply.is_closed() || Instant::now() >= job.deadline) {
                        continue;
                    }
                    if failed || !same_directory(&path, anchor.as_ref()) {
                        failed = true;
                        let _ = job.reply.send(Err(Error::Unavailable));
                        continue;
                    }
                    // Finish takes state before admission to a crypto thread. SQLite
                    // and enrollment transitions remain on this single owner thread.
                    if let Command::Enrollment(endpoint, ref bytes) = job.command {
                        let preparation = (|| {
                            let s = store.as_mut().ok_or(Error::Unavailable)?;
                            if s.needs_upgrade().map_err(map_error)? {
                                return Err(Error::Unavailable);
                            }
                            if enrollment.is_none() {
                                enrollment = Some(Enrollment::new(s)?);
                            }
                            let engine = enrollment.as_mut().ok_or(Error::Unavailable)?;
                            match wire::decode_request(bytes, endpoint)? {
                                wire::Request::RegistrationFinish(v) => {
                                    let task =
                                        engine.take_finish(bytes, endpoint, Instant::now())?;
                                    Ok(Some((task, v.ceremony_id)))
                                }
                                _ => Ok(None),
                            }
                        })();
                        match preparation {
                            Ok(Some((task, id))) => {
                                if crypto.len() >= 2 {
                                    if let Some(e) = enrollment.as_mut() {
                                        e.abort_verification(id);
                                    }
                                    let _ = job.reply.send(Err(Error::Busy));
                                    continue;
                                }
                                #[cfg(test)]
                                let verification_gate =
                                    thread_gate.lock().expect("test gate").take();
                                let tx = completion_tx.clone();
                                let bytes = bytes.clone();
                                let result = thread::Builder::new()
                                    .name("wudo-verifier".into())
                                    .spawn(move || {
                                        #[cfg(test)]
                                        if let Some(gate) = verification_gate {
                                            let _ = gate.started.send(());
                                            let _ = gate.release.recv();
                                        }
                                        let verified = task.run();
                                        if let Some(tx) = tx.upgrade() {
                                            let _ = tx.blocking_send(Job {
                                                command: Command::Completed(
                                                    Box::new(verified),
                                                    bytes,
                                                ),
                                                deadline: job.deadline,
                                                reply: job.reply,
                                            });
                                        }
                                    });
                                match result {
                                    Ok(handle) => crypto.push(handle),
                                    Err(_) => {
                                        if let Some(e) = enrollment.as_mut() {
                                            e.abort_verification(id);
                                        }
                                    }
                                }
                                continue;
                            }
                            Err(error) => {
                                if error == Error::InternalError {
                                    failed = true;
                                }
                                let _ = job.reply.send(Err(error));
                                continue;
                            }
                            Ok(None) => {}
                        }
                    }
                    let result = dispatch(job.command, &path, &mut store, &mut enrollment);
                    if matches!(result, Err(Error::InternalError)) {
                        failed = true;
                    }
                    let _ = job.reply.send(result);
                }
                // Closing the bounded queue releases crypto senders before join.
                // Late results never activate after shutdown.
                drop(rx);
                for handle in crypto {
                    let _ = handle.join();
                }
            })
            .map_err(|_| ())?;
        if ready_rx.recv().map_err(|_| ())?.is_err() {
            let _ = join.join();
            return Err(());
        }
        Ok(Self {
            #[cfg(test)]
            gate,
            client: Client { tx },
            stop,
            join: Some(join),
        })
    }
    #[cfg(test)]
    pub(crate) fn pause_next_verification(
        &self,
    ) -> (oneshot::Receiver<()>, std::sync::mpsc::SyncSender<()>) {
        let (started, rx) = oneshot::channel();
        let (release_tx, release) = std::sync::mpsc::sync_channel(0);
        *self.gate.lock().expect("test gate") = Some(VerificationGate { started, release });
        (rx, release_tx)
    }
    pub(crate) fn client(&self) -> Client {
        self.client.clone()
    }
}
impl Worker {
    pub(crate) fn shutdown(&self) {
        self.stop.store(true, Ordering::Release);
        let (reply, _) = oneshot::channel();
        let _ = self.client.tx.try_send(Job {
            command: Command::Inspect(String::new()),
            deadline: Instant::now(),
            reply,
        });
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.shutdown();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}
fn open_store(path: &std::path::Path) -> Result<Option<Store>, ()> {
    match std::fs::symlink_metadata(path.join("identity.sqlite3")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let has_sidecar=["-journal","-wal","-shm"].iter().any(|suffix| {
                !matches!(std::fs::symlink_metadata(path.join(format!("identity.sqlite3{suffix}"))),Err(e) if e.kind()==std::io::ErrorKind::NotFound)
            });
            if has_sidecar {
                return Err(());
            }
            Ok(None)
        }
        Ok(_) => Store::open_for_upgrade(path).map(Some).map_err(|_| ()),
        Err(_) => Err(()),
    }
}
fn dispatch(
    command: Command,
    path: &std::path::Path,
    store: &mut Option<Store>,
    enrollment: &mut Option<Enrollment>,
) -> Result<Reply, Error> {
    match command {
        Command::Initialize => {
            if store.is_some() {
                return Err(Error::Conflict);
            }
            *store = Some(Store::initialize(path).map_err(map_error)?);
            Ok(Reply::Ready)
        }
        Command::Upgrade => {
            if store.is_none() {
                return Err(Error::Unavailable);
            }
            *store = Some(Store::upgrade(path).map_err(map_error)?);
            Ok(Reply::Ready)
        }
        Command::Configure(origin) => configure(store, enrollment, path, &origin, false),
        Command::Reset(origin) => configure(store, enrollment, path, &origin, true),
        other => {
            let s = store.as_mut().ok_or(Error::Unavailable)?;
            if s.needs_upgrade().map_err(map_error)? {
                return Err(Error::Unavailable);
            }
            match other {
                Command::Administration(bytes) => administration::request(s, &bytes),
                Command::Create(name, label) => s
                    .create_user(&name, &label)
                    .map(Reply::User)
                    .map_err(map_error),
                Command::Inspect(name) => s
                    .user_by_name(&name)
                    .map_err(map_error)?
                    .map(Reply::User)
                    .ok_or(Error::Unavailable),
                Command::Enrollment(endpoint, bytes) => enrollment
                    .as_mut()
                    .ok_or(Error::Unavailable)?
                    .request(&bytes, endpoint, s, Instant::now())
                    .map(Reply::Encoded),
                Command::Completed(verified, bytes) => {
                    let state = enrollment.as_mut().ok_or(Error::Unavailable)?.complete(
                        *verified,
                        s,
                        Instant::now(),
                    )?;
                    let request = wire::decode_request(&bytes, wire::Endpoint::Web)?;
                    let mut out = vec![0; 4096];
                    let n = wire::encode_response(
                        &mut out,
                        &wire::Response::Registered(wire::Registered { state }),
                        &request,
                        wire::Endpoint::Web,
                    )
                    .map_err(|_| Error::InternalError)?;
                    out.truncate(n);
                    Ok(Reply::Encoded(out))
                }
                _ => Err(Error::UnsupportedOperation),
            }
        }
    }
}
fn configure(
    store: &mut Option<Store>,
    enrollment: &mut Option<Enrollment>,
    path: &std::path::Path,
    origin: &str,
    reset: bool,
) -> Result<Reply, Error> {
    wire::InstallationOrigin::parse(origin)?;
    if store
        .as_ref()
        .is_some_and(|s| s.needs_upgrade().unwrap_or(true))
    {
        return Err(Error::Unavailable);
    }
    if reset && let Some(e) = enrollment.as_mut() {
        e.invalidate();
    }
    if store.is_none() {
        *store = Some(Store::initialize(path).map_err(map_error)?);
    }
    let s = store.as_mut().ok_or(Error::Unavailable)?;
    if reset {
        s.reset_installation(origin)
    } else {
        s.configure_installation(origin)
    }
    .map_err(map_error)?;
    if let Some(e) = enrollment.as_mut() {
        e.reload(s)?;
    }
    Ok(Reply::Ready)
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
