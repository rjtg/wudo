mod relay;
mod server;
use std::{net::SocketAddr, path::PathBuf, process::ExitCode};
use wudo_protocol::v2::InstallationOrigin;

struct Config {
    origin: InstallationOrigin,
    listen: SocketAddr,
    assets: PathBuf,
}
fn config(mut args: impl Iterator<Item = std::ffi::OsString>) -> Result<Config, ()> {
    let mut origin = None;
    let mut listen = None;
    let mut assets = None;
    for _ in 0..3 {
        let Some(flag) = args.next() else {
            break;
        };
        let value = args.next().ok_or(())?;
        match flag.to_str() {
            Some("--origin") if origin.is_none() => {
                origin = Some(InstallationOrigin::parse(value.to_str().ok_or(())?).map_err(|_| ())?)
            }
            Some("--listen") if listen.is_none() => {
                listen = Some(
                    value
                        .to_str()
                        .ok_or(())?
                        .parse::<SocketAddr>()
                        .map_err(|_| ())?,
                )
            }
            Some("--assets") if assets.is_none() => assets = Some(PathBuf::from(value)),
            _ => return Err(()),
        }
    }
    if args.next().is_some() {
        return Err(());
    }
    let listen = listen.unwrap_or(SocketAddr::from(([127, 0, 0, 1], 8080)));
    if !listen.ip().is_loopback() || listen.port() == 0 {
        return Err(());
    }
    Ok(Config {
        origin: origin.ok_or(())?,
        listen,
        assets: assets.unwrap_or_else(|| PathBuf::from("ui/wudo-ui/pkg")),
    })
}
fn main() -> ExitCode {
    if rustix::process::geteuid().is_root() {
        eprintln!("wudo-web must run as an unprivileged account.");
        return ExitCode::FAILURE;
    }
    let Ok(c) = config(std::env::args_os().skip(1)) else {
        eprintln!(
            "Usage: wudo-web --origin HTTPS_ORIGIN [--listen LOOPBACK_IP:PORT] [--assets DIRECTORY]"
        );
        return ExitCode::from(2);
    };
    let Ok(app) = server::App::load(&c.origin, &c.assets) else {
        eprintln!("wudo-web: UI assets unavailable; build the UI first.");
        return ExitCode::FAILURE;
    };
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::FAILURE;
    };
    match rt.block_on(server::serve(c.listen, app)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => {
            eprintln!("wudo-web: service unavailable.");
            ExitCode::FAILURE
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arguments_require_fixed_https_origin_and_loopback() {
        for args in [
            vec![],
            vec!["--origin", "http://pi.lan"],
            vec!["--origin", "https://pi.lan", "--listen", "0.0.0.0:8080"],
            vec![
                "--origin",
                "https://pi.lan",
                "--origin",
                "https://other.lan",
            ],
            vec!["--origin", "https://pi.lan", "--listen", "127.0.0.1:0"],
        ] {
            assert!(config(args.into_iter().map(Into::into)).is_err());
        }
        assert!(config(["--origin", "https://pi.lan"].into_iter().map(Into::into)).is_ok());
    }
}
