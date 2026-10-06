//! Only registration messages can cross this relay; the daemon is authoritative.
use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
use wudo_protocol::v2::{self as v, Endpoint, Request};

pub const MAX_REQUEST: usize = 40960;
pub fn registration(bytes: &[u8]) -> Result<Request<'_>, ()> {
    let q = v::decode_request(bytes, Endpoint::Web).map_err(|_| ())?;
    if !matches!(
        q,
        Request::RegistrationBegin(_)
            | Request::RegistrationBeginInsecure
            | Request::RegistrationFinish(_)
    ) {
        return Err(());
    }
    Ok(q)
}
pub async fn exchange(path: &Path, expected_uid: u32, bytes: &[u8]) -> Result<Vec<u8>, ()> {
    let q = registration(bytes)?;
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut s = UnixStream::connect(path).await.map_err(|_| ())?;
        let peer = rustix::net::sockopt::socket_peercred(&s).map_err(|_| ())?;
        if peer.uid.as_raw() != expected_uid {
            return Err(());
        }
        s.write_all(&(bytes.len() as u32).to_be_bytes())
            .await
            .map_err(|_| ())?;
        s.write_all(bytes).await.map_err(|_| ())?;
        s.shutdown().await.map_err(|_| ())?;
        let mut header = [0; 4];
        s.read_exact(&mut header).await.map_err(|_| ())?;
        let n = v::payload_len(header).map_err(|_| ())?;
        if n > q.operation().response_limit() {
            return Err(());
        }
        let mut out = vec![0; n];
        s.read_exact(&mut out).await.map_err(|_| ())?;
        if s.read(&mut [0]).await.map_err(|_| ())? != 0 {
            return Err(());
        }
        v::decode_response(&out, &q, Endpoint::Web).map_err(|_| ())?;
        Ok(out)
    })
    .await
    .map_err(|_| ())?
}

#[cfg(test)]
mod tests {
    use super::*;
    fn encode(q: &Request<'_>, ep: Endpoint) -> Vec<u8> {
        let mut b = vec![0; v::MAX_PAYLOAD];
        let n = v::encode_request(&mut b, q, ep).unwrap();
        b.truncate(n);
        b
    }
    #[test]
    fn relay_has_a_registration_only_allowlist() {
        for q in [
            Request::Status,
            Request::StoreInitialize,
            Request::UserList(v::UserList { after: None }),
            Request::InstallationReset(v::InstallationInitialize {
                origin: v::Text("https://pi.lan"),
            }),
            Request::ActionBegin(v::ActionBegin {
                user_name: v::Name("alice"),
                action_id: v::Name("paperless.start"),
            }),
        ] {
            let ep = if q.operation().allowed(Endpoint::Admin) {
                Endpoint::Admin
            } else {
                Endpoint::Web
            };
            assert!(registration(&encode(&q, ep)).is_err());
        }
        assert!(registration(&encode(&Request::RegistrationBeginInsecure, Endpoint::Web)).is_ok());
    }
    #[test]
    fn relay_checks_peer_reply_bounds_and_eof_without_retry() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                for mode in 0..5 {
                    let dir = tempfile::tempdir().unwrap();
                    let path = dir.path().join("web.sock");
                    let listener = tokio::net::UnixListener::bind(&path).unwrap();
                    let q = Request::RegistrationBeginInsecure;
                    let payload = encode(&q, Endpoint::Web);
                    let mut reply = vec![0; 4096];
                    let n = v::encode_response(
                        &mut reply,
                        &v::Response::Error(v::Error::Unavailable),
                        &q,
                        Endpoint::Web,
                    )
                    .unwrap();
                    reply.truncate(n);
                    let expected = reply.clone();
                    let sent = payload.clone();
                    let task = tokio::spawn(async move {
                        let (mut s, _) = listener.accept().await.unwrap();
                        let mut bytes = Vec::new();
                        s.read_to_end(&mut bytes).await.unwrap();
                        if mode == 1 {
                            assert!(bytes.is_empty());
                            return;
                        }
                        assert_eq!(&bytes[4..], &sent);
                        let len = if mode == 2 { 65537 } else { reply.len() as u32 };
                        s.write_all(&len.to_be_bytes()).await.unwrap();
                        if mode != 2 {
                            if mode == 3 {
                                reply[0] = 0;
                            }
                            s.write_all(&reply).await.unwrap();
                            if mode == 4 {
                                s.write_all(&[0]).await.unwrap();
                            }
                        }
                        s.shutdown().await.unwrap();
                    });
                    let uid = rustix::process::geteuid().as_raw();
                    let result =
                        exchange(&path, if mode == 1 { uid ^ 1 } else { uid }, &payload).await;
                    if mode == 0 {
                        assert_eq!(result.unwrap(), expected);
                    } else {
                        assert!(result.is_err());
                    }
                    task.await.unwrap();
                }
            });
    }
}
