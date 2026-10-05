use std::{
    ffi::OsString,
    io::{self, IsTerminal, Read, Write},
    path::Path,
    process::ExitCode,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
use wudo_protocol::v2::*;

pub(super) fn run(command: &str, args: impl Iterator<Item = OsString>) -> ExitCode {
    let mut args = args;
    // Bounded argument count; UTF-8 and wire validation happen before connecting.
    let values: Vec<_> = args.by_ref().take(5).collect();
    if args.next().is_some() {
        return usage();
    }
    let text: Option<Vec<_>> = values.iter().map(|v| v.to_str()).collect();
    let Some(text) = text else {
        return usage();
    };
    let mut reset = false;
    let mut yes = false;
    let origin = if command == "init" {
        let mut explicit = None;
        let mut flags = text.iter();
        while let Some(flag) = flags.next() {
            match *flag {
                "--origin" if explicit.is_none() => {
                    explicit = Some((*flags.next().unwrap_or(&"")).to_owned())
                }
                "--reset" if !reset => reset = true,
                "--yes" if !yes => yes = true,
                _ => return usage(),
            }
        }
        if yes && !reset {
            return usage();
        }
        if reset && !yes {
            if !io::stdin().is_terminal() {
                eprintln!("wudo init: --reset requires --yes when stdin is not a terminal.");
                return ExitCode::from(2);
            }
            eprint!(
                "Reset deletes all Wudo users, credentials and settings. External resources and action files remain. Type RESET to continue: "
            );
            if io::stderr().flush().is_err() {
                return ExitCode::FAILURE;
            }
            if read_origin(io::stdin().lock()).ok().as_deref() != Some("RESET") {
                eprintln!("Reset cancelled; no request sent.");
                return ExitCode::FAILURE;
            }
        }
        match explicit {
            Some(v) => Some(v),
            None => {
                if !io::stdin().is_terminal() {
                    eprintln!("wudo init: --origin is required when stdin is not a terminal.");
                    return ExitCode::from(2);
                }
                eprint!("Wudo HTTPS address (for example https://wudo.home.example): ");
                if io::stderr().flush().is_err() {
                    return ExitCode::FAILURE;
                }
                match read_origin(io::stdin().lock()) {
                    Ok(v) => Some(v),
                    Err(()) => {
                        eprintln!("wudo init: invalid or missing HTTPS origin.");
                        return ExitCode::from(2);
                    }
                }
            }
        }
    } else {
        None
    };
    let parsed = match origin.as_deref().map(InstallationOrigin::parse).transpose() {
        Ok(v) => v,
        Err(_) => {
            eprintln!(
                "wudo init: invalid HTTPS origin; use a lowercase DNS hostname and optional port, without a path."
            );
            return ExitCode::from(2);
        }
    };
    let request = match (command, text.as_slice()) {
        ("init", _) if reset => Request::InstallationReset(InstallationInitialize {
            origin: Text(parsed.as_ref().expect("init origin checked").as_str()),
        }),
        ("init", _) => Request::InstallationInitialize(InstallationInitialize {
            origin: Text(parsed.as_ref().expect("init origin checked").as_str()),
        }),
        ("upgrade", []) => Request::StoreUpgrade,
        ("user", ["create", name, "--label", label]) => Request::UserCreate(UserCreate {
            name: Name(name),
            label: Label(label),
        }),
        ("user", ["show", name]) => Request::UserInspect(UserInspect { name: Name(name) }),
        _ => return usage(),
    };
    let result = send(&request);
    let Ok(reply) = result else {
        eprintln!(
            "Administrative request failed: connection-or-protocol-error; write outcome may be unknown. Inspect state before retrying."
        );
        return ExitCode::FAILURE;
    };
    match decode_response(&reply, &request, Endpoint::Admin) {
        Ok(Response::StoreReady(_)) => {
            if let Some(origin) = parsed.as_ref() {
                println!(
                    "Wudo initialized for {} (RP ID: {}).",
                    origin.as_str(),
                    origin.rp_id()
                );
            } else {
                println!("Identity store ready.");
            }
        }
        Ok(Response::UserCreated(v)) => println!("User created: {}", uuid(v.user_id)),
        Ok(Response::UserInfo(v)) => println!(
            "User: {}\nName: {:?}\nLabel: {:?}",
            uuid(v.user_id),
            v.name.0,
            v.label.0
        ),
        Ok(Response::Error(Error::Conflict)) if parsed.is_some() => {
            eprintln!(
                "Initialization refused: settings already exist or historical credentials prevent binding. No settings were changed."
            );
            return ExitCode::FAILURE;
        }
        Ok(Response::Error(e)) => {
            eprintln!("Administrative request failed: {e:?}.");
            return ExitCode::FAILURE;
        }
        _ => {
            eprintln!(
                "Administrative request failed: invalid-response; write outcome may be unknown."
            );
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
pub(super) fn send(request: &Request<'_>) -> std::result::Result<Vec<u8>, ()> {
    let mut bytes = [0; 4096];
    let n = encode_request(&mut bytes, request, Endpoint::Admin).map_err(|_| ())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ())?;
    runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(wudo_protocol::DEADLINE_SECONDS),
            exchange(Path::new(wudo_protocol::ADMIN_SOCKET), 0, &bytes[..n]),
        )
        .await
        .map_err(|_| ())?
    })
}
fn read_origin(mut reader: impl Read) -> std::result::Result<String, ()> {
    // Bound allocation even if a terminal/paste never terminates the line.
    let mut bytes = Vec::new();
    // Read one byte at a time from stdin's own locked buffer. Do not add a
    // disposable read-ahead buffer: it could swallow the next prompt's answer.
    for _ in 0..MAX_ORIGIN + 3 {
        let mut byte = [0];
        if reader.read(&mut byte).map_err(|_| ())? == 0 {
            return Err(());
        }
        if byte[0] == b'\n' {
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
            if bytes.len() > MAX_ORIGIN {
                return Err(());
            }
            return String::from_utf8(bytes).map_err(|_| ());
        }
        bytes.push(byte[0]);
    }
    Err(())
}
fn usage() -> ExitCode {
    eprintln!(
        "Usage: wudo init [--origin HTTPS_ORIGIN] [--reset [--yes]] | wudo upgrade | wudo user create NAME --label LABEL | wudo user show NAME"
    );
    ExitCode::from(2)
}
pub(super) fn uuid(id: UserId) -> String {
    let mut text = String::with_capacity(36);
    for (i, b) in id.0.iter().enumerate() {
        if [4, 6, 8, 10].contains(&i) {
            text.push('-');
        }
        text.push_str(&format!("{b:02x}"));
    }
    text
}
async fn exchange(
    path: &Path,
    expected_uid: u32,
    request: &[u8],
) -> std::result::Result<Vec<u8>, ()> {
    let mut stream = UnixStream::connect(path).await.map_err(|_| ())?;
    let peer = rustix::net::sockopt::socket_peercred(&stream).map_err(|_| ())?;
    if peer.uid.as_raw() != expected_uid {
        return Err(());
    }
    stream
        .write_all(&(request.len() as u32).to_be_bytes())
        .await
        .map_err(|_| ())?;
    stream.write_all(request).await.map_err(|_| ())?;
    stream.shutdown().await.map_err(|_| ())?;
    let mut header = [0; 4];
    stream.read_exact(&mut header).await.map_err(|_| ())?;
    let n = wudo_protocol::payload_len(header).map_err(|_| ())?;
    let mut reply = vec![0; n];
    stream.read_exact(&mut reply).await.map_err(|_| ())?;
    let mut extra = [0];
    if stream.read(&mut extra).await.map_err(|_| ())? != 0 {
        return Err(());
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wrong_server_identity_receives_no_administrative_payload() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (server, client) = tokio::sync::oneshot::channel::<()>();
            let path =
                std::env::temp_dir().join(format!("wudo-admin-client-{}.sock", std::process::id()));
            let listener = tokio::net::UnixListener::bind(&path).unwrap();
            let cloned = path.clone();
            let task = tokio::spawn(async move {
                let _ = client.await;
                exchange(&cloned, rustix::process::geteuid().as_raw() ^ 1, b"CANARY").await
            });
            server.send(()).unwrap();
            let (mut s, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            s.read_to_end(&mut bytes).await.unwrap();
            assert!(bytes.is_empty());
            assert!(task.await.unwrap().is_err());
            drop(listener);
            std::fs::remove_file(path).unwrap();
        });
    }
}

#[cfg(test)]
mod prompt_tests {
    use super::*;
    #[test]
    fn bounded_prompt_input_requires_a_complete_line() {
        let mut input = &b"RESET\nhttps://pi.lan\n"[..];
        assert_eq!(read_origin(&mut input).unwrap(), "RESET");
        assert_eq!(read_origin(&mut input).unwrap(), "https://pi.lan");
        assert_eq!(
            read_origin(&b"https://pi.lan\nignored"[..]).unwrap(),
            "https://pi.lan"
        );
        assert_eq!(
            read_origin(&b"https://pi.lan\r\n"[..]).unwrap(),
            "https://pi.lan"
        );
        for input in [
            vec![],
            b"https://pi.lan".to_vec(),
            vec![255, b'\n'],
            vec![b'a'; MAX_ORIGIN + 4],
        ] {
            assert!(read_origin(input.as_slice()).is_err());
        }
        assert!(InstallationOrigin::parse(&read_origin(&b"\n"[..]).unwrap()).is_err());
    }
}
