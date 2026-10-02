mod server;
mod sockets;
mod storage;

use rustix::{
    fs::Mode,
    process::{Gid, getegid, geteuid, umask},
};
use std::{ffi::OsString, process::ExitCode, time::Duration};

fn parse_ids(args: impl Iterator<Item = OsString>) -> Result<(u32, u32), ()> {
    let mut args = args;
    let (mut uid, mut gid) = (None, None);
    for _ in 0..2 {
        let flag = args.next().ok_or(())?;
        let value = args.next().ok_or(())?;
        let value = value.to_str().ok_or(())?;
        if value.is_empty() || value.len() > 10 || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(());
        }
        let value: u32 = value.parse().map_err(|_| ())?;
        if value == 0 || value == u32::MAX {
            return Err(());
        }
        let slot = match flag.to_str() {
            Some("--web-uid") => &mut uid,
            Some("--web-gid") => &mut gid,
            _ => return Err(()),
        };
        if slot.replace(value).is_some() {
            return Err(());
        }
    }
    if args.next().is_some() {
        return Err(());
    }
    Ok((uid.ok_or(())?, gid.ok_or(())?))
}
fn main() -> ExitCode {
    let Ok((uid, gid)) = parse_ids(std::env::args_os().skip(1)) else {
        eprintln!("Usage: wudod --web-uid UID --web-gid GID");
        return ExitCode::from(2);
    };
    if !geteuid().is_root() {
        eprintln!("wudod: root-required");
        return ExitCode::FAILURE;
    }
    // Process-global setting is applied once, before runtime/threads or sockets.
    umask(Mode::from_raw_mode(0o077));
    match run(uid, gid) {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => {
            eprintln!("wudod: startup-or-service-failed");
            ExitCode::FAILURE
        }
    }
}
fn run(uid: u32, gid: u32) -> Result<(), ()> {
    let storage = storage::production()?;
    let dir = sockets::Directory::production()?;
    dir.absent("admin.sock")?;
    dir.absent("web.sock")?;
    let (admin, _admin_guard) = dir.bind("admin.sock", getegid(), Mode::from_raw_mode(0o600))?;
    let (web, _web_guard) = dir.bind("web.sock", Gid::from_raw(gid), Mode::from_raw_mode(0o660))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ())?;
    runtime.block_on(async move {
        let admin = tokio::net::UnixListener::from_std(admin).map_err(|_| ())?;
        let web = tokio::net::UnixListener::from_std(web).map_err(|_| ())?;
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|_| ())?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(|_| ())?;
        let shutdown = async move {
            tokio::select! { _ = terminate.recv() => {}, _ = interrupt.recv() => {} }
        };
        server::serve(
            admin,
            web,
            0,
            uid,
            Duration::from_secs(wudo_protocol::DEADLINE_SECONDS),
            shutdown,
            Some(storage.client()),
        )
        .await
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_arguments_fail_closed() {
        let good = ["--web-uid", "1000", "--web-gid", "1001"];
        assert_eq!(
            parse_ids(good.into_iter().map(OsString::from)),
            Ok((1000, 1001))
        );
        for input in [
            vec![],
            vec!["--web-uid", "0", "--web-gid", "1001"],
            vec!["--web-uid", "1", "--web-uid", "2"],
            vec!["--web-uid", "1", "--web-gid", "4294967295"],
            vec!["--web-uid", "+1", "--web-gid", "2"],
            vec!["--web-uid", "1", "--web-gid", "2", "extra"],
            vec!["--socket", "/tmp/x", "--web-gid", "2"],
        ] {
            assert!(parse_ids(input.into_iter().map(OsString::from)).is_err());
        }
    }
}
