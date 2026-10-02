mod admin;
mod status;

use rustix::fs::{Mode, OFlags, open};
use std::{env, fs::File, io::Read, path::Path, process::ExitCode};
use wudo_core::config::{Config, MAX_INPUT_BYTES};

fn main() -> ExitCode {
    // Consume a fixed number of arguments rather than collecting arbitrary input.
    let mut args = env::args_os().skip(1);
    let command = args.next();
    if let Some(name @ ("init" | "upgrade" | "user")) = command.as_ref().and_then(|v| v.to_str()) {
        return admin::run(name, args);
    }
    if command.as_deref() == Some(std::ffi::OsStr::new("status")) {
        if args.next().is_some() {
            eprintln!("Usage: wudo status");
            return ExitCode::from(2);
        }
        return match status::run() {
            Ok(()) => {
                println!("Daemon IPC reachable (protocol 1); action readiness not checked.");
                ExitCode::SUCCESS
            }
            Err(()) => {
                eprintln!("Daemon status failed: connection-or-protocol-error.");
                ExitCode::FAILURE
            }
        };
    }
    let subcommand = args.next();
    let flag = args.next();
    let path = args.next();
    if command.as_deref() != Some(std::ffi::OsStr::new("config"))
        || subcommand.as_deref() != Some(std::ffi::OsStr::new("validate"))
        || flag.as_deref() != Some(std::ffi::OsStr::new("--file"))
        || path.is_none()
        || args.next().is_some()
    {
        eprintln!("Usage: wudo status | wudo config validate --file PATH");
        return ExitCode::from(2);
    }
    match validate(Path::new(&path.expect("path checked above"))) {
        Ok(config) => {
            println!(
                "Action configuration is structurally valid ({} actions, {} resources, {} managed secrets).",
                config.actions().len(),
                config.resources().len(),
                config.resources().len()
            );
            println!("Deployment readiness was not checked.");
            ExitCode::SUCCESS
        }
        Err(category) => {
            eprintln!("Configuration validation failed: {category}.");
            ExitCode::FAILURE
        }
    }
}

fn validate(path: &Path) -> Result<Config, String> {
    // Offline only: parent symlinks are allowed, ownership is not checked.
    // NOFOLLOW avoids a final-component symlink race; NONBLOCK avoids FIFO waits.
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY,
        Mode::empty(),
    )
    .map_err(|_| "input-unreadable")?;
    let file = File::from(fd);
    let metadata = file.metadata().map_err(|_| "input-unreadable")?;
    if !metadata.is_file() {
        return Err("input-unreadable".into());
    }
    if metadata.len() > MAX_INPUT_BYTES as u64 {
        return Err("input-too-large".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "input-unreadable")?;
    Config::parse(&bytes).map_err(|e| e.to_string())
}
