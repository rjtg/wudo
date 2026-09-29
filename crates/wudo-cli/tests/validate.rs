use rustix::fs::{CWD, Mode, mkfifoat};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};
use wudo_core::config::MAX_INPUT_BYTES;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "wudo-cli-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn run(path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wudo"))
        .args(["config", "validate", "--file"])
        .arg(path)
        .output()
        .unwrap()
}
fn rejected(output: Output) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.len() < 1024);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("TOP_SECRET_CANARY"));
}
#[test]
fn validates_example_and_reports_structural_only() {
    let result = run(Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/paperless.actions.toml"
    )));
    assert!(result.status.success());
    assert!(result.stderr.is_empty());
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains("3 actions, 1 resources, 1 managed secrets"));
    assert!(text.contains("Deployment readiness was not checked"));
}
#[test]
fn invalid_arguments_never_echo_values() {
    for args in [
        vec![],
        vec!["TOP_SECRET_CANARY"],
        vec!["config", "validate", "--file"],
        vec!["config", "validate", "--file", "TOP_SECRET_CANARY", "extra"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_wudo"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&result.stderr).contains("TOP_SECRET_CANARY"));
    }
}
#[test]
fn rejects_symlinks_directories_missing_files_and_fifos() {
    let f = Fixture::new();
    let file = f.write("valid", b"schema_version=1\n[resources]\n[actions]\n");
    let link = f.0.join("link");
    std::os::unix::fs::symlink(file, &link).unwrap();
    rejected(run(&link));
    rejected(run(&f.0));
    rejected(run(&f.0.join("TOP_SECRET_CANARY")));
    let fifo = f.0.join("fifo");
    mkfifoat(CWD, &fifo, Mode::RUSR | Mode::WUSR).unwrap();
    // A blocking open would hang; enforce a deadline and kill the child on failure.
    let mut child = Command::new(env!("CARGO_BIN_EXE_wudo"))
        .args(["config", "validate", "--file"])
        .arg(fifo)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("FIFO blocked validator");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    rejected(child.wait_with_output().unwrap());
}
#[test]
fn rejects_oversized_and_secret_like_malformed_input() {
    let f = Fixture::new();
    rejected(run(&f.write("large", &vec![b'x'; MAX_INPUT_BYTES + 1])));
    rejected(run(&f.write("invalid", b"TOP_SECRET_CANARY='password'")));
    rejected(run(&f.write("encoding", &[255])));
}

#[test]
fn offline_reader_allows_parent_symlinks_but_rejects_unreadable_files() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let f = Fixture::new();
    let dir = f.0.join("real");
    fs::create_dir(&dir).unwrap();
    let file = dir.join("config");
    fs::write(&file, b"schema_version=1\n[resources]\n[actions]\n").unwrap();
    symlink(&dir, f.0.join("parent-link")).unwrap();
    assert!(run(&f.0.join("parent-link/config")).status.success());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
    // Elevated test runners may bypass file modes; exercise denial when effective.
    if fs::File::open(&file).is_err() {
        rejected(run(&file));
    }
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
}
