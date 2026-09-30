use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
use wudo_protocol::{MAX_PAYLOAD, Response, decode_response, encode_request, payload_len};

pub(super) fn run() -> Result<(), ()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ())?;
    runtime.block_on(tokio_status())
}
async fn tokio_status() -> Result<(), ()> {
    tokio::time::timeout(
        Duration::from_secs(wudo_protocol::DEADLINE_SECONDS),
        exchange(Path::new(wudo_protocol::ADMIN_SOCKET), 0),
    )
    .await
    .map_err(|_| ())?
}
async fn exchange(path: &Path, expected_uid: u32) -> Result<(), ()> {
    let mut stream = UnixStream::connect(path).await.map_err(|_| ())?;
    let peer = rustix::net::sockopt::socket_peercred(&stream).map_err(|_| ())?;
    if peer.uid.as_raw() != expected_uid {
        return Err(());
    }
    let bytes = encode_request().map_err(|_| ())?;
    stream
        .write_all(&(bytes.as_ref().len() as u32).to_be_bytes())
        .await
        .map_err(|_| ())?;
    stream.write_all(bytes.as_ref()).await.map_err(|_| ())?;
    stream.shutdown().await.map_err(|_| ())?;
    let mut header = [0; 4];
    stream.read_exact(&mut header).await.map_err(|_| ())?;
    let len = payload_len(header).map_err(|_| ())?;
    let mut payload = [0; MAX_PAYLOAD];
    stream
        .read_exact(&mut payload[..len])
        .await
        .map_err(|_| ())?;
    let mut extra = [0];
    if stream.read(&mut extra).await.map_err(|_| ())? != 0 {
        return Err(());
    }
    if decode_response(&payload[..len]).map_err(|_| ())? != Response::Ready {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;
    use wudo_protocol::{ErrorCode, encode_response};

    #[test]
    fn validates_server_identity_frames_and_eof() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let path =
                std::env::temp_dir().join(format!("wudo-client-{}.sock", std::process::id()));
            let listener = UnixListener::bind(&path).unwrap();
            let uid = rustix::process::geteuid().as_raw();
            for case in 0..7 {
                let client_path = path.clone();
                let client = tokio::spawn(async move {
                    tokio::time::timeout(
                        Duration::from_millis(100),
                        exchange(&client_path, if case == 1 { uid ^ 1 } else { uid }),
                    )
                    .await
                });
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                stream.read_to_end(&mut request).await.unwrap();
                if case == 1 {
                    assert!(request.is_empty());
                } else {
                    let response = encode_response(if case == 2 {
                        Response::Error(ErrorCode::InvalidRequest)
                    } else {
                        Response::Ready
                    })
                    .unwrap();
                    let mut frame = (response.as_ref().len() as u32).to_be_bytes().to_vec();
                    frame.extend_from_slice(response.as_ref());
                    match case {
                        3 => frame.push(0),
                        4 => frame = 4097u32.to_be_bytes().to_vec(),
                        5 => {
                            frame.pop();
                        }
                        _ => {}
                    }
                    stream.write_all(&frame).await.unwrap();
                    if case != 6 {
                        stream.shutdown().await.unwrap();
                    }
                }
                let result = client.await.unwrap();
                if case == 0 {
                    assert_eq!(result.unwrap(), Ok(()));
                } else if case == 6 {
                    assert!(result.is_err());
                } else {
                    assert_eq!(result.unwrap(), Err(()));
                }
            }
            drop(listener);
            std::fs::remove_file(path).unwrap();
        });
    }
}
