//! Closed internal integration facade. No client-selected executable or argv.
use rustix::fs::{self, Mode, OFlags};
use std::{
    collections::BTreeSet,
    io::Read,
    os::fd::AsFd,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use wudo_core::config::{Action, Operation};
use wudo_protocol::v2::{Availability, UnitState};

#[derive(Clone)]
pub struct Integrations {
    shared: Arc<Mutex<Shared>>,
}
#[derive(Default)]
struct Shared {
    targets: BTreeSet<String>,
    children: usize,
}
#[derive(Clone)]
pub enum ConfiguredOperation {
    Systemd { unit: String, start: bool },
}
impl ConfiguredOperation {
    pub fn from_action(action: &Action) -> Option<Self> {
        if action.prerequisite.is_some() || action.timeout_seconds.is_some() {
            return None;
        }
        match &action.operation {
            Operation::SystemdStart { unit } => Some(Self::Systemd {
                unit: unit.clone(),
                start: true,
            }),
            Operation::SystemdStop { unit } => Some(Self::Systemd {
                unit: unit.clone(),
                start: false,
            }),
            _ => None,
        }
    }
}
#[derive(Clone)]
pub struct Observation {
    pub state: UnitState,
    pub availability: Availability,
}
impl Observation {
    pub fn unknown() -> Self {
        Self {
            state: UnitState::Unknown,
            availability: Availability::StateUnavailable,
        }
    }
}
struct Unit {
    id: String,
    state: UnitState,
    loaded: bool,
    job: bool,
}
pub struct Prepared {
    operation: ConfiguredOperation,
    _guard: TargetGuard,
}
struct TargetGuard {
    shared: Arc<Mutex<Shared>>,
    id: String,
}
impl Drop for TargetGuard {
    fn drop(&mut self) {
        if let Ok(mut s) = self.shared.lock() {
            s.targets.remove(&self.id);
        }
    }
}
struct ChildSlot(Arc<Mutex<Shared>>);
impl Drop for ChildSlot {
    fn drop(&mut self) {
        if let Ok(mut s) = self.0.lock() {
            s.children -= 1;
        }
    }
}
pub enum Submission {
    Accepted,
    Unknown,
    NotSubmitted,
}
impl Default for Integrations {
    fn default() -> Self {
        Self {
            shared: Arc::new(Mutex::new(Shared::default())),
        }
    }
}
fn unit_name(s: &str) -> bool {
    let Some(stem) = s
        .strip_suffix(".service")
        .or_else(|| s.strip_suffix(".target"))
    else {
        return false;
    };
    !stem.is_empty()
        && s.len() <= 128
        && stem.as_bytes()[0].is_ascii_alphanumeric()
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn parse(bytes: &[u8]) -> Result<Unit, ()> {
    if bytes.len() > 4096 {
        return Err(());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ())?;
    let mut fields = std::collections::BTreeMap::new();
    for line in text.lines() {
        if line.len() > 512 || line.contains('\0') {
            return Err(());
        }
        let (key, value) = line.split_once('=').ok_or(())?;
        if !["Id", "LoadState", "ActiveState", "Job"].contains(&key)
            || fields.insert(key, value).is_some()
        {
            return Err(());
        }
    }
    if fields.len() != 4 {
        return Err(());
    }
    let id = fields["Id"];
    if !unit_name(id) {
        return Err(());
    }
    let job = fields["Job"];
    let job = if job.is_empty() {
        false
    } else {
        if !job.bytes().all(|b| b.is_ascii_digit()) || job.parse::<u32>().map_err(|_| ())? == 0 {
            return Err(());
        }
        true
    };
    let state = match fields["ActiveState"] {
        "active" => UnitState::Active,
        "inactive" => UnitState::Inactive,
        "failed" => UnitState::Failed,
        "activating" | "deactivating" | "reloading" => UnitState::Transitioning,
        _ => UnitState::Unknown,
    };
    Ok(Unit {
        id: id.into(),
        state,
        loaded: fields["LoadState"] == "loaded",
        job,
    })
}
fn observation(unit: &Unit, start: bool, busy: bool) -> Observation {
    let availability = if !unit.loaded || unit.state == UnitState::Unknown {
        Availability::StateUnavailable
    } else if busy || unit.job || unit.state == UnitState::Transitioning {
        Availability::Busy
    } else if start && unit.state == UnitState::Active {
        Availability::AlreadyRunning
    } else if !start && unit.state != UnitState::Active {
        Availability::AlreadyStopped
    } else {
        Availability::Available
    };
    Observation {
        state: unit.state,
        availability,
    }
}
fn trusted_executable() -> Result<std::os::fd::OwnedFd, ()> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut fd = fs::open("/", flags, Mode::empty()).map_err(|_| ())?;
    for component in [Some("usr"), Some("bin"), None] {
        let s = fs::fstat(&fd).map_err(|_| ())?;
        if s.st_uid != 0 || s.st_mode & 0o022 != 0 {
            return Err(());
        }
        no_acl(&fd)?;
        if let Some(c) = component {
            fd = fs::openat(&fd, c, flags, Mode::empty()).map_err(|_| ())?;
        }
    }
    let leaf = fs::openat(
        &fd,
        "systemctl",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ())?;
    let s = fs::fstat(&leaf).map_err(|_| ())?;
    if s.st_uid != 0
        || s.st_mode & 0o6022 != 0
        || s.st_mode & 0o111 == 0
        || fs::FileType::from_raw_mode(s.st_mode) != fs::FileType::RegularFile
    {
        return Err(());
    }
    no_acl(&leaf)?;
    if !matches!(
        fs::fgetxattr(&leaf, "security.capability", &mut [0; 0]),
        Err(rustix::io::Errno::NODATA)
    ) {
        return Err(());
    }
    Ok(leaf)
}
fn no_acl(fd: impl AsFd) -> Result<(), ()> {
    for name in ["system.posix_acl_access", "system.posix_acl_default"] {
        if !matches!(
            fs::fgetxattr(&fd, name, &mut [0; 0]),
            Err(rustix::io::Errno::NODATA)
        ) {
            return Err(());
        }
    }
    Ok(())
}
#[derive(Clone, Copy)]
enum CallFailure {
    BeforeSpawn,
    AfterSpawn,
}
impl From<()> for CallFailure {
    fn from(_: ()) -> Self {
        Self::BeforeSpawn
    }
}
impl Integrations {
    fn call(
        &self,
        verb: &str,
        unit: &str,
        deadline: Instant,
    ) -> Result<(bool, Vec<u8>), CallFailure> {
        if !unit_name(unit) || Instant::now() >= deadline {
            return Err(CallFailure::BeforeSpawn);
        }
        let executable = trusted_executable()?;
        let before = fs::fstat(&executable).map_err(|_| ())?;
        let slot = {
            let mut s = self.shared.lock().map_err(|_| ())?;
            if s.children >= 4 {
                return Err(CallFailure::BeforeSpawn);
            }
            s.children += 1;
            ChildSlot(self.shared.clone())
        };
        let mut command = systemctl_command(verb, unit)?;
        if Instant::now() >= deadline {
            return Err(CallFailure::BeforeSpawn);
        }
        let result = collect(&mut command, deadline).and_then(|result| {
            let after = trusted_executable().map_err(|_| CallFailure::AfterSpawn)?;
            let after = fs::fstat(&after).map_err(|_| CallFailure::AfterSpawn)?;
            if before.st_dev != after.st_dev
                || before.st_ino != after.st_ino
                || before.st_ctime != after.st_ctime
                || before.st_ctime_nsec != after.st_ctime_nsec
            {
                return Err(CallFailure::AfterSpawn);
            }
            Ok(result)
        });
        drop(slot);
        result
    }
    fn unit(&self, name: &str, deadline: Instant) -> Result<Unit, ()> {
        let (ok, out) = self.call("show", name, deadline).map_err(|_| ())?;
        if !ok {
            return Err(());
        }
        parse(&out)
    }
    pub fn observe(&self, op: &ConfiguredOperation, deadline: Instant) -> Observation {
        let ConfiguredOperation::Systemd { unit, start } = op;
        let Ok(u) = self.unit(unit, deadline) else {
            return Observation::unknown();
        };
        let busy = self
            .shared
            .lock()
            .map(|s| s.targets.contains(&u.id))
            .unwrap_or(true);
        observation(&u, *start, busy)
    }
    pub fn prepare(&self, op: ConfiguredOperation) -> Result<Prepared, Availability> {
        let deadline = Instant::now() + Duration::from_secs(2);
        let ConfiguredOperation::Systemd { unit, start } = &op;
        let u = self
            .unit(unit, deadline)
            .map_err(|_| Availability::StateUnavailable)?;
        {
            let mut s = self
                .shared
                .lock()
                .map_err(|_| Availability::StateUnavailable)?;
            if !s.targets.insert(u.id.clone()) {
                return Err(Availability::Busy);
            }
        }
        let guard = TargetGuard {
            shared: self.shared.clone(),
            id: u.id.clone(),
        };
        let fresh = self
            .unit(unit, deadline)
            .map_err(|_| Availability::StateUnavailable)?;
        if fresh.id != u.id {
            return Err(Availability::StateUnavailable);
        }
        let available = observation(&fresh, *start, false).availability;
        if available != Availability::Available {
            return Err(available);
        }
        Ok(Prepared {
            operation: ConfiguredOperation::Systemd {
                unit: fresh.id,
                start: *start,
            },
            _guard: guard,
        })
    }
    /// Only the state owner may call this after final authentication/grant checks.
    pub fn submit(&self, prepared: Prepared, timeout: Duration) -> Submission {
        let ConfiguredOperation::Systemd { unit, start } = &prepared.operation;
        match self.call(
            if *start { "start" } else { "stop" },
            unit,
            Instant::now() + timeout,
        ) {
            Ok((true, _)) => Submission::Accepted,
            Err(CallFailure::BeforeSpawn) => Submission::NotSubmitted,
            _ => Submission::Unknown,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_properties_and_availability() {
        let source = "Id=demo.service\nLoadState=loaded\nActiveState=inactive\nJob=\n";
        let u = parse(source.as_bytes()).unwrap();
        assert_eq!(
            observation(&u, true, false).availability,
            Availability::Available
        );
        assert_eq!(
            observation(&u, false, false).availability,
            Availability::AlreadyStopped
        );
        for bad in [
            source.replace("Job=\n", ""),
            source.replace("Job=\n", "Job=0\n"),
            source.replace("Job=\n", "Job=4294967296\n"),
            format!("{source}Job=\n"),
            source.replace("demo.service", "/bin/sh"),
            format!("{source}Extra=x\n"),
        ] {
            assert!(parse(bad.as_bytes()).is_err());
        }
        let u = parse(source.replace("Job=\n", "Job=12\n").as_bytes()).unwrap();
        assert_eq!(
            observation(&u, true, false).availability,
            Availability::Busy
        );
        let u = parse(source.replace("inactive", "future-state").as_bytes()).unwrap();
        assert_eq!(
            observation(&u, true, false).availability,
            Availability::StateUnavailable
        );
    }
}

fn collect(command: &mut Command, deadline: Instant) -> Result<(bool, Vec<u8>), CallFailure> {
    if Instant::now() >= deadline {
        return Err(CallFailure::BeforeSpawn);
    }
    let mut child = command.spawn().map_err(|_| CallFailure::BeforeSpawn)?;
    let result = (|| {
        let mut out = child.stdout.take().ok_or(())?;
        let mut err = child.stderr.take().ok_or(())?;
        for fd in [out.as_fd(), err.as_fd()] {
            let flags = fs::fcntl_getfl(fd).map_err(|_| ())?;
            fs::fcntl_setfl(fd, flags | OFlags::NONBLOCK).map_err(|_| ())?;
        }
        let (mut stdout, mut total, mut eof_out, mut eof_err) = (Vec::new(), 0usize, false, false);
        loop {
            if Instant::now() >= deadline {
                return Err(());
            }
            for (reader, eof, keep) in [
                (&mut out as &mut dyn Read, &mut eof_out, true),
                (&mut err as &mut dyn Read, &mut eof_err, false),
            ] {
                let mut buf = [0; 1024];
                match reader.read(&mut buf) {
                    Ok(0) => *eof = true,
                    Ok(n) => {
                        total += n;
                        if total > 16384 {
                            return Err(());
                        }
                        if keep {
                            stdout.extend_from_slice(&buf[..n]);
                            if stdout.len() > 4096 {
                                return Err(());
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err(()),
                }
            }
            if let Some(status) = child.try_wait().map_err(|_| ())?
                && eof_out
                && eof_err
            {
                return Ok((status.success(), stdout));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    } // Slot/target stay held through reap.

    result.map_err(|_| CallFailure::AfterSpawn)
}

#[cfg(test)]
mod process_tests {
    use super::*;
    use std::io::Write;

    // Run only as a child of the tests below. No shell or host service involved.
    #[test]
    #[ignore]
    fn fixture_child() {
        match std::env::var("WUDO_PROCESS_FIXTURE").unwrap().as_str() {
            "both" => {
                std::io::stdout().write_all(b"properties").unwrap();
                std::io::stderr().write_all(&[b'e'; 8192]).unwrap();
            }
            "stdout-overflow" => std::io::stdout().write_all(&[b'x'; 8192]).unwrap(),
            "stderr-overflow" => std::io::stderr().write_all(&[b'x'; 20000]).unwrap(),
            "timeout" => std::thread::sleep(Duration::from_secs(30)),
            "nonzero" => std::process::exit(17),
            _ => panic!("fixture mode"),
        }
    }
    fn fixture(mode: &str) -> Command {
        let mut c = Command::new(std::env::current_exe().unwrap());
        c.args([
            "--ignored",
            "--exact",
            "integrations::process_tests::fixture_child",
            "--nocapture",
        ])
        .env_clear()
        .env("WUDO_PROCESS_FIXTURE", mode)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        c
    }
    #[test]
    fn bounded_dual_pipe_collection_and_nonzero() {
        let (ok, out) = collect(
            &mut fixture("both"),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_or_else(|_| panic!("collection"));
        assert!(ok);
        assert!(out.windows(10).any(|v| v == b"properties"));
        let (ok, _) = collect(
            &mut fixture("nonzero"),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_or_else(|_| panic!("collection"));
        assert!(!ok);
        for mode in ["stdout-overflow", "stderr-overflow", "timeout"] {
            let start = Instant::now();
            assert!(matches!(
                collect(&mut fixture(mode), start + Duration::from_millis(200)),
                Err(CallFailure::AfterSpawn)
            ));
            assert!(start.elapsed() < Duration::from_secs(5));
        }
    }
    #[test]
    fn expired_and_failed_spawn_are_definitely_not_submitted() {
        assert!(matches!(
            collect(&mut fixture("timeout"), Instant::now()),
            Err(CallFailure::BeforeSpawn)
        ));
        assert!(matches!(
            collect(
                &mut Command::new("/nonexistent/wudo-test-fixture"),
                Instant::now() + Duration::from_secs(1)
            ),
            Err(CallFailure::BeforeSpawn)
        ));
    }
    #[test]
    fn state_matrix_and_hostile_names_fail_closed() {
        for name in [
            "-demo.service",
            "*.service",
            "demo@a.service",
            "x/y.service",
            "x.service\n",
            "a.socket",
            "x;stop.service",
        ] {
            assert!(!unit_name(name));
        }
        for state in [
            UnitState::Active,
            UnitState::Inactive,
            UnitState::Failed,
            UnitState::Transitioning,
            UnitState::Unknown,
        ] {
            let mut unit = Unit {
                id: "demo.service".into(),
                state,
                loaded: true,
                job: false,
            };
            assert_eq!(
                observation(&unit, true, false).availability == Availability::Available,
                matches!(state, UnitState::Inactive | UnitState::Failed)
            );
            assert_eq!(
                observation(&unit, false, false).availability == Availability::Available,
                state == UnitState::Active
            );
            assert_ne!(
                observation(&unit, true, true).availability,
                Availability::Available
            );
            unit.job = true;
            assert_ne!(
                observation(&unit, true, false).availability,
                Availability::Available
            );
            unit.job = false;
            unit.loaded = false;
            assert_eq!(
                observation(&unit, true, false).availability,
                Availability::StateUnavailable
            );
        }
    }
}

fn systemctl_command(verb: &str, unit: &str) -> Result<Command, CallFailure> {
    if !unit_name(unit) {
        return Err(CallFailure::BeforeSpawn);
    }
    let mut command = Command::new("/usr/bin/systemctl");
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("PATH", "/usr/bin:/bin")
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "cat")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(["--system", "--no-pager", "--no-ask-password"]);
    if verb == "show" {
        command.args(["show", "--all", "--property=Id,LoadState,ActiveState,Job"]);
    } else if matches!(verb, "start" | "stop") {
        command.args(["--no-block", "--job-mode=fail", verb]);
    } else {
        return Err(CallFailure::BeforeSpawn);
    }
    command.args(["--", unit]);
    Ok(command)
}

#[cfg(test)]
mod command_tests {
    use super::*;
    #[test]
    fn fixed_executable_arguments_environment_and_no_fallback_verbs() {
        for verb in ["show", "start", "stop"] {
            let c = systemctl_command(verb, "demo.service").unwrap_or_else(|_| panic!("command"));
            assert_eq!(c.get_program(), "/usr/bin/systemctl");
            let args: Vec<_> = c.get_args().map(|s| s.to_str().unwrap()).collect();
            let mut expected = vec!["--system", "--no-pager", "--no-ask-password"];
            if verb == "show" {
                expected.extend(["show", "--all", "--property=Id,LoadState,ActiveState,Job"]);
            } else {
                expected.extend(["--no-block", "--job-mode=fail", verb]);
            }
            expected.extend(["--", "demo.service"]);
            assert_eq!(args, expected);
            let env: Vec<_> = c
                .get_envs()
                .map(|(k, v)| (k.to_str().unwrap(), v.unwrap().to_str().unwrap()))
                .collect();
            assert_eq!(
                env,
                vec![
                    ("LANG", "C"),
                    ("LC_ALL", "C"),
                    ("PATH", "/usr/bin:/bin"),
                    ("SYSTEMD_COLORS", "0"),
                    ("SYSTEMD_PAGER", "cat")
                ]
            );
            assert_eq!(c.get_current_dir().unwrap(), std::path::Path::new("/"));
        }
        for verb in ["restart", "enable", "reboot", "sh", "start --all"] {
            assert!(systemctl_command(verb, "demo.service").is_err());
        }
    }
    #[test]
    fn canonical_target_guard_survives_requester_handle_drop() {
        let backend = Integrations::default();
        let shared = backend.shared.clone();
        shared
            .lock()
            .unwrap()
            .targets
            .insert("canonical.service".into());
        let guard = TargetGuard {
            shared: shared.clone(),
            id: "canonical.service".into(),
        };
        drop(backend);
        assert!(
            !shared
                .lock()
                .unwrap()
                .targets
                .insert("canonical.service".into())
        );
        drop(guard);
        assert!(
            shared
                .lock()
                .unwrap()
                .targets
                .insert("canonical.service".into())
        );
    }
}
