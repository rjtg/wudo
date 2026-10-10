use std::{future::Future, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
    time::{Instant, timeout_at},
};
use wudo_protocol::{MAX_PAYLOAD, Response, decode_request, encode_response};

pub(crate) fn authorized(actual_uid: u32, allowed_uid: u32) -> bool {
    actual_uid == allowed_uid
}

#[cfg(test)]
async fn exchange(stream: UnixStream) -> Result<(), ()> {
    exchange_with_store(
        stream,
        wudo_protocol::v2::Endpoint::Admin,
        None,
        Instant::now() + Duration::from_secs(5),
    )
    .await
}
async fn exchange_with_store(
    mut stream: UnixStream,
    endpoint: wudo_protocol::v2::Endpoint,
    storage: Option<crate::storage::Client>,
    deadline: Instant,
) -> Result<(), ()> {
    use wudo_protocol::v2;
    let mut header = [0; 4];
    stream.read_exact(&mut header).await.map_err(|_| ())?;
    let len = v2::payload_len(header).map_err(|_| ())?;
    let mut payload = vec![0; len];
    stream.read_exact(&mut payload).await.map_err(|_| ())?;
    let mut extra = [0];
    if stream.read(&mut extra).await.map_err(|_| ())? != 0 {
        return Err(());
    }
    let version = v2::envelope_version(&payload).map_err(|_| ())?;
    let bytes = if version == 2 {
        let request = match v2::decode_request(&payload, endpoint) {
            Ok(r) => r,
            Err(error) => {
                let mut bytes = [0; 4096];
                let n = v2::encode_response(
                    &mut bytes,
                    &v2::Response::Error(error),
                    &v2::Request::Status,
                    endpoint,
                )
                .map_err(|_| ())?;
                stream
                    .write_all(&(n as u32).to_be_bytes())
                    .await
                    .map_err(|_| ())?;
                stream.write_all(&bytes[..n]).await.map_err(|_| ())?;
                return stream.shutdown().await.map_err(|_| ());
            }
        };
        let result = match (&request, storage) {
            (v2::Request::Status, _) => None,
            (_, Some(client)) => {
                use crate::storage::Command;
                let command = match &request {
                    v2::Request::ViewBegin(_)
                    | v2::Request::ViewFinish(_)
                    | v2::Request::ViewActions(_) => Some(Command::Viewing(payload.clone())),
                    v2::Request::StoreInitialize => Some(Command::Initialize),
                    v2::Request::InstallationInitialize(v) => {
                        Some(Command::Configure(v.origin.0.into()))
                    }
                    v2::Request::InstallationReset(v) => Some(Command::Reset(v.origin.0.into())),
                    v2::Request::StoreUpgrade => Some(Command::Upgrade),
                    v2::Request::UserCreate(v) => {
                        Some(Command::Create(v.name.0.into(), v.label.0.into()))
                    }
                    v2::Request::UserList(_)
                    | v2::Request::ActionList(_)
                    | v2::Request::GrantList(_)
                    | v2::Request::GrantCreate(_)
                    | v2::Request::GrantRevoke(_)
                    | v2::Request::CredentialList(_)
                    | v2::Request::CredentialInspect(_)
                    | v2::Request::CredentialRevoke(_) => {
                        Some(Command::Administration(payload.clone()))
                    }
                    v2::Request::UserInspect(v) => Some(Command::Inspect(v.name.0.into())),
                    _ => None,
                };
                Some(match command {
                    Some(c) => client.request(c, deadline.into_std()).await,
                    None if matches!(
                        request,
                        v2::Request::EnrollmentOpen(_)
                            | v2::Request::EnrollmentInspect(_)
                            | v2::Request::EnrollmentCancel(_)
                            | v2::Request::EnrollmentApprove(_)
                            | v2::Request::RegistrationBegin(_)
                            | v2::Request::RegistrationBeginInsecure
                            | v2::Request::RegistrationFinish(_)
                    ) =>
                    {
                        client
                            .enrollment(endpoint, payload.clone(), deadline.into_std())
                            .await
                    }
                    None => Err(v2::Error::UnsupportedOperation),
                })
            }
            _ => Some(Err(v2::Error::Unavailable)),
        };
        if let Some(Ok(crate::storage::Reply::Encoded(out))) = result {
            out
        } else {
            let response = match &result {
                None => v2::Response::Status(v2::StatusResult {
                    status: v2::Ready::Ready,
                }),
                Some(Err(e)) => v2::Response::Error(*e),
                Some(Ok(crate::storage::Reply::Ready)) => {
                    v2::Response::StoreReady(v2::StoreReady {
                        state: v2::Ready::Ready,
                    })
                }
                Some(Ok(crate::storage::Reply::Encoded(_))) => unreachable!(),
                Some(Ok(crate::storage::Reply::User(u))) => {
                    if matches!(request, v2::Request::UserCreate(_)) {
                        v2::Response::UserCreated(v2::UserCreated {
                            user_id: v2::UserId(*u.id.as_bytes()),
                        })
                    } else {
                        v2::Response::UserInfo(v2::UserInfo {
                            user_id: v2::UserId(*u.id.as_bytes()),
                            name: v2::Name(&u.name),
                            label: v2::Label(&u.label),
                        })
                    }
                }
            };
            let mut out = vec![0; request.operation().response_limit()];
            let n = v2::encode_response(&mut out, &response, &request, endpoint).map_err(|_| ())?;
            out.truncate(n);
            out
        }
    } else {
        if len > MAX_PAYLOAD {
            return Err(());
        }
        let response = match decode_request(&payload) {
            Ok(_) => Response::Ready,
            Err(e) => Response::Error(e),
        };
        encode_response(response).map_err(|_| ())?.as_ref().to_vec()
    };
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await
        .map_err(|_| ())?;
    stream.write_all(&bytes).await.map_err(|_| ())?;
    stream.shutdown().await.map_err(|_| ())
}

fn admit(
    stream: UnixStream,
    uid: u32,
    capacity: &Arc<Semaphore>,
    tasks: &mut JoinSet<()>,
    duration: Duration,
    endpoint: wudo_protocol::v2::Endpoint,
    storage: Option<crate::storage::Client>,
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
        // Dropping the reply receiver cancels queued work, never a started transaction.
        let _ = timeout_at(
            deadline,
            exchange_with_store(stream, endpoint, storage, deadline),
        )
        .await;
    });
}

pub(crate) async fn serve(
    admin: UnixListener,
    web: UnixListener,
    admin_uid: u32,
    web_uid: u32,
    duration: Duration,
    shutdown: impl Future<Output = ()>,
    storage: Option<crate::storage::Client>,
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
                Ok((stream, _)) => admit(stream, admin_uid, &admin_capacity, &mut tasks, duration, wudo_protocol::v2::Endpoint::Admin, storage.clone()),
                Err(_) => break Err(()),
            },
            result = web.accept() => match result {
                Ok((stream, _)) => admit(stream, web_uid, &web_capacity, &mut tasks, duration, wudo_protocol::v2::Endpoint::Web, storage.clone()),
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
                if body == b"CANARY" {
                    assert!(response.is_empty());
                    assert!(task.await.unwrap().is_err());
                } else {
                    assert_eq!(decode_response(&response[4..]), Ok(expected));
                    task.await.unwrap().unwrap();
                }
                assert!(!String::from_utf8_lossy(&response).contains("CANARY"));
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
                admit(
                    s,
                    uid,
                    &web,
                    &mut tasks,
                    Duration::from_secs(5),
                    wudo_protocol::v2::Endpoint::Admin,
                    None,
                );
            }
            assert_eq!(web.available_permits(), 0);
            let (mut denied, s) = UnixStream::pair().unwrap();
            admit(
                s,
                uid,
                &web,
                &mut tasks,
                Duration::from_secs(5),
                wudo_protocol::v2::Endpoint::Admin,
                None,
            );
            assert_eq!(denied.read(&mut [0]).await.unwrap(), 0);
            let (c, s) = UnixStream::pair().unwrap();
            admit(
                s,
                uid,
                &admin,
                &mut tasks,
                Duration::from_secs(5),
                wudo_protocol::v2::Endpoint::Admin,
                None,
            );
            let response = request(c, encode_request().unwrap().as_ref()).await;
            assert_eq!(decode_response(&response[4..]), Ok(Response::Ready));
            let (mut denied, s) = UnixStream::pair().unwrap();
            admit(
                s,
                uid ^ 1,
                &admin,
                &mut tasks,
                Duration::from_secs(5),
                wudo_protocol::v2::Endpoint::Admin,
                None,
            );
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
            let task = tokio::spawn(serve(
                admin,
                web,
                uid,
                uid,
                Duration::from_secs(5),
                async {
                    let _ = stopped.await;
                },
                None,
            ));
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

#[cfg(test)]
mod administration_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use wudo_protocol::v2 as v;
    async fn call(
        req: &v::Request<'_>,
        endpoint: v::Endpoint,
        client: crate::storage::Client,
    ) -> Vec<u8> {
        let (mut a, b) = UnixStream::pair().unwrap();
        let task = tokio::spawn(exchange_with_store(
            b,
            endpoint,
            Some(client),
            Instant::now() + Duration::from_secs(5),
        ));
        let mut buf = [0; 4096];
        let n = v::encode_request(&mut buf, req, v::Endpoint::Admin).unwrap();
        a.write_all(&(n as u32).to_be_bytes()).await.unwrap();
        a.write_all(&buf[..n]).await.unwrap();
        a.shutdown().await.unwrap();
        let mut reply = Vec::new();
        a.read_to_end(&mut reply).await.unwrap();
        let result = task.await.unwrap();
        if endpoint == v::Endpoint::Web {
            result.unwrap();
            assert!(matches!(
                v::decode_response(&reply[4..], &v::Request::Status, v::Endpoint::Web).unwrap(),
                v::Response::Error(v::Error::NotPermitted)
            ));
        } else {
            result.unwrap();
        }
        reply
    }
    #[test]
    fn old_schema_admits_upgrade_then_reconciles_startup_catalog() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = wudo_store::Store::initialize(dir.path()).unwrap();
        store.configure_installation("https://pi.lan").unwrap();
        drop(store);
        let db = rusqlite::Connection::open(dir.path().join("identity.sqlite3")).unwrap();
        db.execute_batch("DROP TABLE grants; DROP TABLE actions; PRAGMA user_version=3;")
            .unwrap();
        drop(db);
        let config = wudo_core::config::Config::parse(include_bytes!(
            "../../../examples/paperless.actions.toml"
        ))
        .unwrap();
        let worker =
            crate::storage::Worker::start_configured(dir.path().into(), None, config).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let q = v::Request::ActionList(v::ActionList { after: None });
            let bytes = call(&q, v::Endpoint::Admin, worker.client()).await;
            assert!(matches!(v::decode_response(&bytes[4..], &q, v::Endpoint::Admin).unwrap(), v::Response::Error(v::Error::Unavailable)));
            let upgrade = v::Request::StoreUpgrade;
            let bytes = call(&upgrade, v::Endpoint::Admin, worker.client()).await;
            assert!(!matches!(v::decode_response(&bytes[4..], &upgrade, v::Endpoint::Admin).unwrap(), v::Response::Error(_)));
            let bytes = call(&q, v::Endpoint::Admin, worker.client()).await;
            assert!(matches!(v::decode_response(&bytes[4..], &q, v::Endpoint::Admin).unwrap(), v::Response::ActionPage(p) if p.actions.0.len() == 3));
        });
    }
    #[test]
    fn configured_grants_reconcile_restart_and_reset_over_ipc() {
        use crate::storage::Worker;
        use wudo_core::config::Config;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let source = include_str!("../../../examples/paperless.actions.toml");
        let catalog = || Config::parse(source.as_bytes()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let worker = Worker::start_configured(dir.path().into(), None, catalog()).unwrap();
        let user = rt.block_on(async {
            for req in [
                v::Request::InstallationInitialize(v::InstallationInitialize { origin: v::Text("https://pi.lan") }),
                v::Request::UserCreate(v::UserCreate { name: v::Name("alice"), label: v::Label("Alice") }),
            ] {
                let bytes = call(&req, v::Endpoint::Admin, worker.client()).await;
                assert!(!matches!(v::decode_response(&bytes[4..], &req, v::Endpoint::Admin).unwrap(), v::Response::Error(_)));
            }
            let q = v::Request::UserInspect(v::UserInspect { name: v::Name("alice") });
            let bytes = call(&q, v::Endpoint::Admin, worker.client()).await;
            let v::Response::UserInfo(u) = v::decode_response(&bytes[4..], &q, v::Endpoint::Admin).unwrap() else { panic!("user") };
            let user = u.user_id;
            for q in [
                v::Request::ActionList(v::ActionList { after: None }),
                v::Request::GrantList(v::GrantQuery { user_id: user, after: None }),
                v::Request::GrantCreate(v::GrantRef { user_id: user, action_id: v::Name("paperless.start") }),
                v::Request::GrantRevoke(v::GrantRef { user_id: user, action_id: v::Name("paperless.start") }),
            ] { call(&q, v::Endpoint::Web, worker.client()).await; }
            let q = v::Request::GrantList(v::GrantQuery { user_id: user, after: None });
            let bytes = call(&q, v::Endpoint::Admin, worker.client()).await;
            assert!(matches!(v::decode_response(&bytes[4..], &q, v::Endpoint::Admin).unwrap(), v::Response::GrantPage(p) if p.actions.0.is_empty()));
            for action in ["paperless.start", "missing"] {
                let q = v::Request::GrantCreate(v::GrantRef { user_id: user, action_id: v::Name(action) });
                let bytes = call(&q, v::Endpoint::Admin, worker.client()).await;
                let response = v::decode_response(&bytes[4..], &q, v::Endpoint::Admin).unwrap();
                if action == "missing" { assert!(matches!(response, v::Response::Error(v::Error::Unavailable))); }
                else { assert!(matches!(response, v::Response::GrantChanged(g) if g.granted)); }
            }
            user
        });
        drop(worker);
        for (text, expected) in [
            (source.to_owned(), 1),
            (source.replace("paperless.service", "changed.service"), 0),
        ] {
            let worker = Worker::start_configured(
                dir.path().into(),
                None,
                Config::parse(text.as_bytes()).unwrap(),
            )
            .unwrap();
            rt.block_on(async {
                let q = v::Request::GrantList(v::GrantQuery { user_id: user, after: None });
                let bytes = call(&q, v::Endpoint::Admin, worker.client()).await;
                assert!(matches!(v::decode_response(&bytes[4..], &q, v::Endpoint::Admin).unwrap(), v::Response::GrantPage(p) if p.actions.0.len() == expected));
            });
        }
        let worker = Worker::start_configured(dir.path().into(), None, catalog()).unwrap();
        rt.block_on(async {
            let q = v::Request::InstallationReset(v::InstallationInitialize { origin: v::Text("https://pi.lan") });
            let bytes = call(&q, v::Endpoint::Admin, worker.client()).await;
            assert!(!matches!(v::decode_response(&bytes[4..], &q, v::Endpoint::Admin).unwrap(), v::Response::Error(_)));
            let q = v::Request::ActionList(v::ActionList { after: None });
            let bytes = call(&q, v::Endpoint::Admin, worker.client()).await;
            assert!(matches!(v::decode_response(&bytes[4..], &q, v::Endpoint::Admin).unwrap(), v::Response::ActionPage(p) if p.actions.0.len() == 3));
            let q = v::Request::GrantList(v::GrantQuery { user_id: user, after: None });
            let bytes = call(&q, v::Endpoint::Admin, worker.client()).await;
            assert!(matches!(v::decode_response(&bytes[4..], &q, v::Endpoint::Admin).unwrap(), v::Response::Error(v::Error::Unavailable)));
        });
    }
    #[test]
    fn administrative_roundtrip_and_restart_reject_web_operations() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let worker = crate::storage::Worker::start(dir.path().into(), None).unwrap();
        rt.block_on(async {
            for req in [
                v::Request::InstallationInitialize(v::InstallationInitialize {
                    origin: v::Text("https://wudo.example.test"),
                }),
                v::Request::StoreUpgrade,
                v::Request::UserCreate(v::UserCreate {
                    name: v::Name("alice"),
                    label: v::Label("Alice"),
                }),
                v::Request::UserInspect(v::UserInspect {
                    name: v::Name("alice"),
                }),
            ] {
                call(&req, v::Endpoint::Web, worker.client()).await;
            }
            assert!(!dir.path().join("identity.sqlite3").exists());
            for req in [
                v::Request::InstallationInitialize(v::InstallationInitialize {
                    origin: v::Text("https://wudo.example.test"),
                }),
                v::Request::UserCreate(v::UserCreate {
                    name: v::Name("alice"),
                    label: v::Label("Alice"),
                }),
                v::Request::StoreUpgrade,
            ] {
                let reply = call(&req, v::Endpoint::Admin, worker.client()).await;
                assert!(!matches!(
                    v::decode_response(&reply[4..], &req, v::Endpoint::Admin).unwrap(),
                    v::Response::Error(_)
                ));
            }
            let req = v::Request::InstallationInitialize(v::InstallationInitialize {
                origin: v::Text("https://other.example.test"),
            });
            let reply = call(&req, v::Endpoint::Admin, worker.client()).await;
            assert!(matches!(
                v::decode_response(&reply[4..], &req, v::Endpoint::Admin).unwrap(),
                v::Response::Error(v::Error::Conflict)
            ));
        });
        drop(worker);
        let persisted = wudo_store::Store::open(dir.path()).unwrap();
        assert_eq!(
            persisted.installation_origin().unwrap().unwrap().as_str(),
            "https://wudo.example.test"
        );
        drop(persisted);
        let worker = crate::storage::Worker::start(dir.path().into(), None).unwrap();
        rt.block_on(async {
            let req = v::Request::UserInspect(v::UserInspect {
                name: v::Name("alice"),
            });
            let reply = call(&req, v::Endpoint::Admin, worker.client()).await;
            let v::Response::UserInfo(user) =
                v::decode_response(&reply[4..], &req, v::Endpoint::Admin).unwrap()
            else {
                panic!("missing user")
            };
            assert_eq!(user.name.0, "alice");
            assert_eq!(user.label.0, "Alice");
        });
    }
}

#[cfg(test)]
mod enrollment_tests;

#[cfg(test)]
mod viewing_tests;
