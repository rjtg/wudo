use crate::relay;
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use std::{io::Read, net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};
use tower::ServiceExt;
use wudo_protocol::v2::InstallationOrigin;

pub struct App {
    origin: String,
    host: String,
    js: Bytes,
    wasm: Bytes,
    #[cfg(test)]
    daemon: Option<(std::path::PathBuf, u32)>,
}
impl App {
    pub fn load(origin: &InstallationOrigin, path: &Path) -> Result<Arc<Self>, ()> {
        fn asset(path: &Path, limit: usize) -> Result<Bytes, ()> {
            let file = std::fs::File::open(path).map_err(|_| ())?;
            let meta = file.metadata().map_err(|_| ())?;
            if !meta.is_file() || meta.len() > limit as u64 {
                return Err(());
            }
            let mut bytes = Vec::new();
            file.take(limit as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| ())?;
            if bytes.is_empty() || bytes.len() > limit {
                return Err(());
            }
            Ok(bytes.into())
        }
        Ok(Arc::new(Self {
            origin: origin.as_str().into(),
            host: origin.as_str().strip_prefix("https://").ok_or(())?.into(),
            js: asset(&path.join("wudo_ui.js"), 1024 * 1024)?,
            wasm: asset(&path.join("wudo_ui_bg.wasm"), 8 * 1024 * 1024)?,
            #[cfg(test)]
            daemon: None,
        }))
    }
}
fn single<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    let mut all = headers.get_all(key).iter();
    let first = all.next()?.to_str().ok()?;
    if all.next().is_some() {
        None
    } else {
        Some(first)
    }
}
fn response(status: StatusCode, kind: &'static str, body: impl Into<Body>) -> Response {
    let mut r = Response::new(body.into());
    *r.status_mut() = status;
    for (k, v) in [
        ("content-type", kind),
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ),
        (
            "permissions-policy",
            "publickey-credentials-create=(self), publickey-credentials-get=(self)",
        ),
    ] {
        r.headers_mut().insert(k, HeaderValue::from_static(v));
    }
    r
}
fn error(status: StatusCode) -> Response {
    response(
        status,
        "text/plain; charset=utf-8",
        "Enrollment request unavailable.\n",
    )
}
async fn handle(State(app): State<Arc<App>>, req: Request) -> Response {
    if req.uri().query().is_some() || single(req.headers(), "host") != Some(app.host.as_str()) {
        return error(StatusCode::BAD_REQUEST);
    }
    if req.method() == "GET" {
        return match req.uri().path() {
            "/" => response(
                StatusCode::OK,
                "text/html; charset=utf-8",
                include_str!("../../../ui/wudo-ui/index.html"),
            ),
            "/style.css" => response(
                StatusCode::OK,
                "text/css; charset=utf-8",
                include_str!("../../../ui/wudo-ui/style.css"),
            ),
            "/start.js" => response(
                StatusCode::OK,
                "text/javascript; charset=utf-8",
                include_str!("../../../ui/wudo-ui/start.js"),
            ),
            "/wudo_ui.js" => response(
                StatusCode::OK,
                "text/javascript; charset=utf-8",
                app.js.clone(),
            ),
            "/wudo_ui_bg.wasm" => response(StatusCode::OK, "application/wasm", app.wasm.clone()),
            _ => error(StatusCode::NOT_FOUND),
        };
    }
    if req.method() != "POST" || req.uri().path() != "/api/enroll" {
        return error(StatusCode::NOT_FOUND);
    }
    if single(req.headers(), "origin") != Some(app.origin.as_str())
        || (req.headers().contains_key("sec-fetch-site")
            && single(req.headers(), "sec-fetch-site") != Some("same-origin"))
    {
        return error(StatusCode::FORBIDDEN);
    }
    if single(req.headers(), "content-type") != Some("application/cbor")
        || req.headers().contains_key("content-encoding")
    {
        return error(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let Ok(bytes) = to_bytes(req.into_body(), relay::MAX_REQUEST).await else {
        return error(StatusCode::PAYLOAD_TOO_LARGE);
    };
    if relay::registration(&bytes).is_err() {
        return error(StatusCode::BAD_REQUEST);
    }
    let target = (Path::new(wudo_protocol::WEB_SOCKET), 0);
    #[cfg(test)]
    let target = app
        .daemon
        .as_ref()
        .map(|(p, u)| (p.as_path(), *u))
        .unwrap_or(target);
    match relay::exchange(target.0, target.1, &bytes).await {
        Ok(reply) => response(StatusCode::OK, "application/cbor", reply),
        Err(()) => error(StatusCode::BAD_GATEWAY),
    }
}
fn router(app: Arc<App>) -> Router {
    Router::new().fallback(handle).with_state(app)
}
pub async fn serve(address: SocketAddr, app: Arc<App>) -> Result<(), ()> {
    let listener = TcpListener::bind(address).await.map_err(|_| ())?;
    let capacity = Arc::new(Semaphore::new(16));
    let router = router(app);
    let mut tasks = JoinSet::new();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| ())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| ())?;
    loop {
        tokio::select! {
            biased;
            _=term.recv()=>break,
            _=interrupt.recv()=>break,
            done=tasks.join_next(),if !tasks.is_empty()=>{if done.is_some_and(|r|r.is_err()){return Err(());}},
            next=listener.accept()=>{
                let (stream,_)=next.map_err(|_| ())?;
                let Ok(permit)=capacity.clone().try_acquire_owned()else{drop(stream);continue;};
                let app=router.clone();
                tasks.spawn(async move{
                    let _permit=permit;
                    connection(stream, app, Duration::from_secs(10)).await;
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn connection(stream: tokio::net::TcpStream, app: Router, deadline: Duration) {
    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        app.clone().oneshot(req.map(Body::new))
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .keep_alive(false)
        .max_headers(32)
        .max_buf_size(16384)
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(3));
    let _ = tokio::time::timeout(
        deadline,
        builder.serve_connection(hyper_util::rt::TokioIo::new(stream), service),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    fn app() -> Arc<App> {
        Arc::new(App {
            origin: "https://pi.lan".into(),
            host: "pi.lan".into(),
            js: Bytes::from_static(b"js"),
            wasm: Bytes::from_static(b"wasm"),
            daemon: None,
        })
    }
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }
    #[test]
    fn allowed_http_request_relays_exact_cbor_and_returns_daemon_outcome() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use wudo_protocol::v2 as v;
        runtime().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("web.sock");
            let listener = tokio::net::UnixListener::bind(&path).unwrap();
            let mut app = app();
            Arc::get_mut(&mut app).unwrap().daemon =
                Some((path, rustix::process::geteuid().as_raw()));
            let q = v::Request::RegistrationBegin(v::RegistrationBegin {
                ticket: v::Ticket([7; 32]),
            });
            let mut payload = vec![0; 4096];
            let n = v::encode_request(&mut payload, &q, v::Endpoint::Web).unwrap();
            payload.truncate(n);
            let sent = payload.clone();
            let daemon = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                socket.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(&bytes[4..], sent);
                assert_eq!(
                    u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize,
                    sent.len()
                );
                let q = v::decode_request(&sent, v::Endpoint::Web).unwrap();
                let mut out = [0; 4096];
                let n = v::encode_response(
                    &mut out,
                    &v::Response::Error(v::Error::Unavailable),
                    &q,
                    v::Endpoint::Web,
                )
                .unwrap();
                socket.write_all(&(n as u32).to_be_bytes()).await.unwrap();
                socket.write_all(&out[..n]).await.unwrap();
                socket.shutdown().await.unwrap();
            });
            let req = Request::builder()
                .method("POST")
                .uri("/api/enroll")
                .header("host", "pi.lan")
                .header("origin", "https://pi.lan")
                .header("content-type", "application/cbor")
                .body(Body::from(payload))
                .unwrap();
            let reply = router(app).oneshot(req).await.unwrap();
            assert_eq!(reply.status(), StatusCode::OK);
            assert_eq!(reply.headers()["content-type"], "application/cbor");
            let bytes = to_bytes(reply.into_body(), 4096).await.unwrap();
            assert!(matches!(
                v::decode_response(&bytes, &q, v::Endpoint::Web).unwrap(),
                v::Response::Error(v::Error::Unavailable)
            ));
            daemon.await.unwrap();
        });
    }
    #[test]
    fn network_connection_closes_after_one_request_and_bounds_slow_clients() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        runtime().block_on(async {
            for incomplete in [false, true] {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let server = tokio::spawn(async move {
                    let (stream, _) = listener.accept().await.unwrap();
                    connection(stream, router(app()), Duration::from_millis(100)).await;
                });
                let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
                let request = if incomplete {
                    &b"GET / HTTP/1.1\r\nHost:"[..]
                } else {
                    &b"GET / HTTP/1.1\r\nHost: pi.lan\r\n\r\nGET / HTTP/1.1\r\nHost: pi.lan\r\n\r\n"
                        [..]
                };
                client.write_all(request).await.unwrap();
                let mut out = Vec::new();
                let _ = tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut out))
                    .await
                    .unwrap();
                if incomplete {
                    assert!(out.is_empty());
                } else {
                    assert_eq!(
                        String::from_utf8_lossy(&out)
                            .matches("HTTP/1.1 200 OK")
                            .count(),
                        1
                    );
                }
                server.await.unwrap();
            }
        });
    }
    #[test]
    fn headers_and_operation_allowlist_fail_closed() {
        use wudo_protocol::v2 as v;
        runtime().block_on(async {
            for (key, value, append, status) in [
                ("origin", "https://evil.lan", true, 403),
                ("host", "evil.lan", true, 400),
                ("sec-fetch-site", "cross-site", false, 403),
                ("content-type", "application/json", true, 415),
                ("content-encoding", "gzip", false, 415),
            ] {
                let mut req = Request::builder()
                    .method("POST")
                    .uri("/api/enroll")
                    .header("host", "pi.lan")
                    .header("origin", "https://pi.lan")
                    .header("content-type", "application/cbor")
                    .body(Body::empty())
                    .unwrap();
                if append {
                    req.headers_mut()
                        .append(key, HeaderValue::from_static(value));
                } else {
                    req.headers_mut()
                        .insert(key, HeaderValue::from_static(value));
                }
                assert_eq!(
                    router(app()).oneshot(req).await.unwrap().status().as_u16(),
                    status
                );
            }
            for q in [
                v::Request::Status,
                v::Request::StoreInitialize,
                v::Request::UserList(v::UserList { after: None }),
            ] {
                let mut b = vec![0; 4096];
                let n = v::encode_request(&mut b, &q, v::Endpoint::Admin).unwrap();
                b.truncate(n);
                let req = Request::builder()
                    .method("POST")
                    .uri("/api/enroll")
                    .header("host", "pi.lan")
                    .header("origin", "https://pi.lan")
                    .header("content-type", "application/cbor")
                    .body(Body::from(b))
                    .unwrap();
                assert_eq!(
                    router(app()).oneshot(req).await.unwrap().status(),
                    StatusCode::BAD_REQUEST
                );
            }
        });
    }
    #[test]
    fn http_policy_rejects_cross_origin_admin_and_oversize_bodies() {
        runtime().block_on(async {
            for (method, path, host, origin, content, body, status) in [
                ("GET", "/", "pi.lan", "", "", vec![], 200),
                ("GET", "/../secret", "pi.lan", "", "", vec![], 404),
                ("GET", "/?ticket=CANARY", "pi.lan", "", "", vec![], 400),
                ("GET", "/", "evil.lan", "", "", vec![], 400),
                (
                    "POST",
                    "/api/enroll",
                    "pi.lan",
                    "https://evil.lan",
                    "application/cbor",
                    vec![],
                    403,
                ),
                (
                    "POST",
                    "/api/enroll",
                    "pi.lan",
                    "",
                    "application/cbor",
                    vec![],
                    403,
                ),
                (
                    "POST",
                    "/api/enroll",
                    "pi.lan",
                    "https://pi.lan",
                    "text/plain",
                    vec![],
                    415,
                ),
                (
                    "POST",
                    "/api/enroll",
                    "pi.lan",
                    "https://pi.lan",
                    "application/cbor",
                    vec![0; 40961],
                    413,
                ),
                (
                    "POST",
                    "/api/enroll",
                    "pi.lan",
                    "https://pi.lan",
                    "application/cbor",
                    b"CANARY".to_vec(),
                    400,
                ),
            ] {
                let req = Request::builder()
                    .method(method)
                    .uri(path)
                    .header("host", host)
                    .header("origin", origin)
                    .header("content-type", content)
                    .body(Body::from(body))
                    .unwrap();
                let reply = router(app()).oneshot(req).await.unwrap();
                assert_eq!(reply.status().as_u16(), status);
                assert_eq!(reply.headers()["cache-control"], "no-store");
                assert!(!reply.headers().contains_key("access-control-allow-origin"));
                assert!(
                    !String::from_utf8_lossy(&to_bytes(reply.into_body(), 65536).await.unwrap())
                        .contains("CANARY")
                );
            }
        });
    }
}
