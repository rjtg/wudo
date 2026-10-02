use std::{ffi::OsString, path::Path, process::ExitCode, time::Duration};
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
    let request = match (command, text.as_slice()) {
        ("init", []) => Request::StoreInitialize,
        ("upgrade", []) => Request::StoreUpgrade,
        ("user", ["create", name, "--label", label]) => Request::UserCreate(UserCreate {
            name: Name(name),
            label: Label(label),
        }),
        ("user", ["show", name]) => Request::UserInspect(UserInspect { name: Name(name) }),
        _ => return usage(),
    };
    let mut bytes = [0; 4096];
    let Ok(n) = encode_request(&mut bytes, &request, Endpoint::Admin) else {
        return usage();
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::FAILURE;
    };
    let result = runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(wudo_protocol::DEADLINE_SECONDS),
            exchange(Path::new(wudo_protocol::ADMIN_SOCKET), 0, &bytes[..n]),
        )
        .await
        .map_err(|_| ())?
    });
    let Ok(reply) = result else {
        eprintln!(
            "Administrative request failed: connection-or-protocol-error; write outcome may be unknown. Inspect state before retrying."
        );
        return ExitCode::FAILURE;
    };
    match decode_response(&reply, &request, Endpoint::Admin) {
        Ok(Response::StoreReady(_)) => println!("Identity store ready."),
        Ok(Response::UserCreated(v)) => println!("User created: {}", uuid(v.user_id)),
        Ok(Response::UserInfo(v)) => println!(
            "User: {}\nName: {:?}\nLabel: {:?}",
            uuid(v.user_id),
            v.name.0,
            v.label.0
        ),
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
fn usage() -> ExitCode {
    eprintln!(
        "Usage: wudo init | wudo upgrade | wudo user create NAME --label LABEL | wudo user show NAME"
    );
    ExitCode::from(2)
}
fn uuid(id: UserId) -> String {
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
