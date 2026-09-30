use std::{future::Future, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
    time::{Instant, timeout_at},
};
use wudo_protocol::{MAX_PAYLOAD, Response, decode_request, encode_response, payload_len};

pub(crate) fn authorized(actual_uid: u32, allowed_uid: u32) -> bool {
    actual_uid == allowed_uid
}

async fn exchange(mut stream: UnixStream) -> Result<(), ()> {
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
    let response = match decode_request(&payload[..len]) {
        Ok(_) => Response::Ready,
        Err(e) => Response::Error(e),
    };
    let bytes = encode_response(response).map_err(|_| ())?;
    stream
        .write_all(&(bytes.as_ref().len() as u32).to_be_bytes())
        .await
        .map_err(|_| ())?;
    stream.write_all(bytes.as_ref()).await.map_err(|_| ())?;
    stream.shutdown().await.map_err(|_| ())
}

fn admit(
    stream: UnixStream,
    uid: u32,
    capacity: &Arc<Semaphore>,
    tasks: &mut JoinSet<()>,
    duration: Duration,
) {
    let deadline = Instant::now() + duration;
    let Ok(permit) = Arc::clone(capacity).try_acquire_owned() else {
        return;
    };
    let Ok(peer) = rustix::net::sockopt::socket_peercred(&stream) else {
        return;
    };
    if !authorized(peer.uid.as_raw(), uid) {
        return;
    }
    tasks.spawn(async move {
        let _permit = permit;
        // Cancellation is safe only because this slice has no side effects.
        let _ = timeout_at(deadline, exchange(stream)).await;
    });
}

pub(crate) async fn serve(
    admin: UnixListener,
    web: UnixListener,
    admin_uid: u32,
    web_uid: u32,
    duration: Duration,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ()> {
    let admin_capacity = Arc::new(Semaphore::new(4));
    let web_capacity = Arc::new(Semaphore::new(4));
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);
    let result = loop {
        tokio::select! {
            // Drain completed tasks before accepting more, avoiding accumulation
            // of JoinSet entries even when accepted connections finish quickly.
            biased;
            _ = &mut shutdown => break Ok(()),
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if completed.is_some_and(|r| r.is_err()) { break Err(()); }
            }
            result = admin.accept() => match result {
                Ok((stream, _)) => admit(stream, admin_uid, &admin_capacity, &mut tasks, duration),
                Err(_) => break Err(()),
            },
            result = web.accept() => match result {
                Ok((stream, _)) => admit(stream, web_uid, &web_capacity, &mut tasks, duration),
                Err(_) => break Err(()),
            },
        }
    };
    drop(admin);
    drop(web);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use wudo_protocol::{ErrorCode, decode_response, encode_request};
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }
    async fn request(mut client: UnixStream, bytes: &[u8]) -> Vec<u8> {
        client
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .await
            .unwrap();
        client.write_all(bytes).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        response
    }
    #[test]
    fn exchange_status_errors_and_half_close() {
        runtime().block_on(async {
            for (body, expected) in [
                (encode_request().unwrap().as_ref().to_vec(), Response::Ready),
                (
                    b"CANARY".to_vec(),
                    Response::Error(ErrorCode::InvalidRequest),
                ),
            ] {
                let (client, server) = UnixStream::pair().unwrap();
                let task = tokio::spawn(exchange(server));
                let response = request(client, &body).await;
                assert_eq!(decode_response(&response[4..]), Ok(expected));
                assert!(!String::from_utf8_lossy(&response).contains("CANARY"));
                task.await.unwrap().unwrap();
            }
        });
    }
    #[test]
    fn frame_errors_and_absolute_deadline() {
        runtime().block_on(async {
            for raw in [
                vec![0, 0, 0, 0],
                vec![0, 0, 16, 1],
                vec![0, 0],
                vec![0, 0, 0, 2, 0],
                vec![0, 0, 0, 1, 0, 1],
            ] {
                let (mut client, server) = UnixStream::pair().unwrap();
                let task = tokio::spawn(exchange(server));
                client.write_all(&raw).await.unwrap();
                client.shutdown().await.unwrap();
                let mut response = Vec::new();
                let _ = client.read_to_end(&mut response).await;
                assert!(response.is_empty());
                assert!(task.await.unwrap().is_err());
            }
            let (mut client, server) = UnixStream::pair().unwrap();
            let task = tokio::spawn(async move {
                timeout_at(Instant::now() + Duration::from_millis(60), exchange(server)).await
            });
            client.write_all(&[0]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(35)).await;
            client.write_all(&[0]).await.unwrap();
            assert!(task.await.unwrap().is_err());
        });
    }
    #[test]
    fn admission_checks_peer_and_reserves_endpoint_capacity() {
        runtime().block_on(async {
            assert!(authorized(0, 0));
            assert!(!authorized(1000, 0));
            assert!(!authorized(0, 1000));
            let uid = rustix::process::geteuid().as_raw();
            let web = Arc::new(Semaphore::new(4));
            let admin = Arc::new(Semaphore::new(4));
            let mut tasks = JoinSet::new();
            let mut clients = Vec::new();
            for _ in 0..4 {
                let (c, s) = UnixStream::pair().unwrap();
                clients.push(c);
                admit(s, uid, &web, &mut tasks, Duration::from_secs(5));
            }
            assert_eq!(web.available_permits(), 0);
            let (mut denied, s) = UnixStream::pair().unwrap();
            admit(s, uid, &web, &mut tasks, Duration::from_secs(5));
            assert_eq!(denied.read(&mut [0]).await.unwrap(), 0);
            let (c, s) = UnixStream::pair().unwrap();
            admit(s, uid, &admin, &mut tasks, Duration::from_secs(5));
            let response = request(c, encode_request().unwrap().as_ref()).await;
            assert_eq!(decode_response(&response[4..]), Ok(Response::Ready));
            let (mut denied, s) = UnixStream::pair().unwrap();
            admit(s, uid ^ 1, &admin, &mut tasks, Duration::from_secs(5));
            assert_eq!(denied.read(&mut [0]).await.unwrap(), 0);
            drop(clients);
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            assert_eq!(web.available_permits(), 4);
            assert_eq!(admin.available_permits(), 4);
        });
    }
    #[test]
    fn listener_shutdown_cancels_incomplete_connections() {
        runtime().block_on(async {
            let base = std::env::temp_dir().join(format!("wudo-shutdown-{}", std::process::id()));
            std::fs::create_dir(&base).unwrap();
            let admin = UnixListener::bind(base.join("admin")).unwrap();
            let web = UnixListener::bind(base.join("web")).unwrap();
            let uid = rustix::process::geteuid().as_raw();
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(serve(admin, web, uid, uid, Duration::from_secs(5), async {
                let _ = stopped.await;
            }));
            let mut idle = UnixStream::connect(base.join("web")).await.unwrap();
            let client = UnixStream::connect(base.join("admin")).await.unwrap();
            let reply = request(client, encode_request().unwrap().as_ref()).await;
            assert_eq!(decode_response(&reply[4..]), Ok(Response::Ready));
            tokio::task::yield_now().await;
            stop.send(()).unwrap();
            tokio::time::timeout(Duration::from_millis(500), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(idle.read(&mut [0]).await.unwrap(), 0);
            std::fs::remove_dir_all(base).unwrap();
        });
    }
}
