use super::*;
use crate::storage::{Client, Worker};
use std::{fs, os::unix::fs::PermissionsExt};
use webauthn_authenticator_rs::{AuthenticatorBackendHashedClientData, softpasskey::SoftPasskey};
use webauthn_rs::prelude::*;
use wudo_protocol::v2 as v;
const ORIGIN: &str = "https://wudo.example.test";
fn setup() -> (tempfile::TempDir, Worker) {
    let d = tempfile::tempdir().unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let w = Worker::start(d.path().into(), None).unwrap();
    (d, w)
}
fn encode(req: &v::Request<'_>, ep: v::Endpoint) -> Vec<u8> {
    let mut b = vec![0; v::MAX_PAYLOAD];
    let n = v::encode_request(&mut b, req, ep).unwrap();
    b.truncate(n);
    b
}
async fn raw(client: Client, ep: v::Endpoint, payload: Vec<u8>) -> Vec<u8> {
    let (mut peer, server) = UnixStream::pair().unwrap();
    let task = tokio::spawn(async move {
        exchange_with_store(
            server,
            ep,
            Some(client),
            Instant::now() + Duration::from_secs(5),
        )
        .await
    });
    peer.write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .unwrap();
    peer.write_all(&payload).await.unwrap();
    peer.shutdown().await.unwrap();
    let mut reply = Vec::new();
    peer.read_to_end(&mut reply).await.unwrap();
    task.await.unwrap().unwrap();
    let n = v::payload_len(reply[..4].try_into().unwrap()).unwrap();
    assert_eq!(reply.len(), n + 4);
    reply[4..].to_vec()
}
async fn call(client: Client, req: &v::Request<'_>, ep: v::Endpoint) -> Vec<u8> {
    raw(client, ep, encode(req, ep)).await
}
async fn open(client: Client, mode: v::Mode) -> (v::EnrollmentId, v::Request<'static>, v::UserId) {
    let req = v::Request::UserCreate(v::UserCreate {
        name: v::Name("alice"),
        label: v::Label("Alice"),
    });
    let reply = call(client.clone(), &req, v::Endpoint::Admin).await;
    let v::Response::UserCreated(user) =
        v::decode_response(&reply, &req, v::Endpoint::Admin).unwrap()
    else {
        panic!("user")
    };
    let req = v::Request::EnrollmentOpen(v::EnrollmentOpen {
        user_id: user.user_id,
        mode,
    });
    let reply = call(client, &req, v::Endpoint::Admin).await;
    let v::Response::Opened(opened) = v::decode_response(&reply, &req, v::Endpoint::Admin).unwrap()
    else {
        panic!("open")
    };
    (
        opened.enrollment_id,
        opened
            .ticket
            .map(|ticket| v::Request::RegistrationBegin(v::RegistrationBegin { ticket }))
            .unwrap_or(v::Request::RegistrationBeginInsecure),
        user.user_id,
    )
}
async fn init(client: Client) {
    let req = v::Request::InstallationInitialize(v::InstallationInitialize {
        origin: v::Text(ORIGIN),
    });
    let reply = call(client, &req, v::Endpoint::Admin).await;
    assert!(matches!(
        v::decode_response(&reply, &req, v::Endpoint::Admin).unwrap(),
        v::Response::StoreReady(_)
    ));
}
async fn signed_finish(client: Client, begin: &v::Request<'_>) -> (Vec<u8>, Vec<u8>) {
    let reply = call(client, begin, v::Endpoint::Web).await;
    let v::Response::RegistrationChallenge(v) =
        v::decode_response(&reply, begin, v::Endpoint::Web).unwrap()
    else {
        panic!("challenge")
    };
    let b64 = |b: &[u8]| Base64UrlSafeData::from(b.to_vec());
    let o = v.options;
    let options:CreationChallengeResponse=serde_json::from_value(serde_json::json!({"publicKey":{
        "rp":{"id":o.rp.id.0,"name":o.rp.name.0},"user":{"id":b64(&o.user.id.0),"name":o.user.name.0,"displayName":o.user.display_name.0},
        "challenge":b64(&o.challenge.0),"timeout":o.timeout_ms.0,
        "pubKeyCredParams":o.algorithms.0.iter().map(|a|serde_json::json!({"type":"public-key","alg":a})).collect::<Vec<_>>(),
        "authenticatorSelection":{"userVerification":"required","requireResidentKey":false},"attestation":"none"
    }})).unwrap();
    let data=serde_json::to_vec(&serde_json::json!({"type":"webauthn.create","challenge":options.public_key.challenge,"origin":ORIGIN})).unwrap();
    let response = SoftPasskey::new(true)
        .perform_register(
            openssl::sha::sha256(&data).to_vec(),
            options.public_key,
            120000,
        )
        .unwrap();
    let req = v::Request::RegistrationFinish(v::RegistrationFinish {
        ceremony_id: v.ceremony_id,
        credential_id: v::Blob(response.raw_id.as_ref()),
        client_data: v::Blob(&data),
        attestation_object: v::Blob(response.response.attestation_object.as_ref()),
        client_extensions: v::RegistrationExtensions {
            resident_key: None,
            cred_protect: None,
        },
    });
    (
        encode(&req, v::Endpoint::Web),
        response.raw_id.as_ref().to_vec(),
    )
}
#[test]
fn enrollment_over_ipc_requires_approval_and_survives_restart() {
    let (dir, worker) = setup();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (user, key) = rt.block_on(async {
        let client = worker.client();
        init(client.clone()).await;
        let (id, begin, user) = open(client.clone(), v::Mode::Confirm).await;
        let (payload, key) = signed_finish(client.clone(), &begin).await;
        let reply = raw(client.clone(), v::Endpoint::Web, payload.clone()).await;
        let req = v::decode_request(&payload, v::Endpoint::Web).unwrap();
        assert!(matches!(
            v::decode_response(&reply, &req, v::Endpoint::Web).unwrap(),
            v::Response::Registered(v::Registered {
                state: v::RegistrationState::PendingApproval
            })
        ));
        let inspect = v::Request::EnrollmentInspect(v::EnrollmentRef { enrollment_id: id });
        let reply = call(client.clone(), &inspect, v::Endpoint::Admin).await;
        let v::Response::CandidateInspection(candidate) =
            v::decode_response(&reply, &inspect, v::Endpoint::Admin).unwrap()
        else {
            panic!("candidate")
        };
        let approve = v::Request::EnrollmentApprove(v::EnrollmentApprove {
            enrollment_id: id,
            candidate_id: candidate.candidate_id,
        });
        let denied = raw(
            client.clone(),
            v::Endpoint::Web,
            encode(&approve, v::Endpoint::Admin),
        )
        .await;
        assert!(matches!(
            v::decode_response(&denied, &v::Request::Status, v::Endpoint::Web).unwrap(),
            v::Response::Error(v::Error::NotPermitted)
        ));
        let reply = call(client.clone(), &approve, v::Endpoint::Admin).await;
        assert!(matches!(
            v::decode_response(&reply, &approve, v::Endpoint::Admin).unwrap(),
            v::Response::Activated(_)
        ));
        let replay = raw(client, v::Endpoint::Web, payload.clone()).await;
        assert!(matches!(
            v::decode_response(&replay, &req, v::Endpoint::Web).unwrap(),
            v::Response::Error(v::Error::Unavailable)
        ));
        (user, key)
    });
    drop(worker);
    let s = wudo_store::Store::open(dir.path()).unwrap();
    assert!(
        s.credential_for_authentication(wudo_store::UserId::from_bytes(user.0).unwrap(), &key)
            .unwrap()
            .is_some()
    );
}
#[test]
fn reset_or_cancel_during_crypto_keeps_status_responsive_and_blocks_activation() {
    for reset in [false, true] {
        let (dir, worker) = setup();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let key = rt.block_on(async {
            let client = worker.client();
            init(client.clone()).await;
            let (id, begin, _) = open(client.clone(), v::Mode::Insecure).await;
            let (payload, key) = signed_finish(client.clone(), &begin).await;
            let (started, release) = worker.pause_next_verification();
            let cloned = client.clone();
            let copy = payload.clone();
            let running = tokio::spawn(async move { raw(cloned, v::Endpoint::Web, copy).await });
            tokio::time::timeout(Duration::from_secs(2), started)
                .await
                .unwrap()
                .unwrap();
            let status = v::Request::Status;
            let reply = call(client.clone(), &status, v::Endpoint::Web).await;
            assert!(matches!(
                v::decode_response(&reply, &status, v::Endpoint::Web).unwrap(),
                v::Response::Status(_)
            ));
            let req = if reset {
                v::Request::InstallationReset(v::InstallationInitialize {
                    origin: v::Text(ORIGIN),
                })
            } else {
                v::Request::EnrollmentCancel(v::EnrollmentRef { enrollment_id: id })
            };
            let denied = raw(
                client.clone(),
                v::Endpoint::Web,
                encode(&req, v::Endpoint::Admin),
            )
            .await;
            assert!(matches!(
                v::decode_response(&denied, &status, v::Endpoint::Web).unwrap(),
                v::Response::Error(v::Error::NotPermitted)
            ));
            let reply = call(client, &req, v::Endpoint::Admin).await;
            assert!(!matches!(
                v::decode_response(&reply, &req, v::Endpoint::Admin).unwrap(),
                v::Response::Error(_)
            ));
            release.send(()).unwrap();
            let reply = running.await.unwrap();
            let req = v::decode_request(&payload, v::Endpoint::Web).unwrap();
            assert!(matches!(
                v::decode_response(&reply, &req, v::Endpoint::Web).unwrap(),
                v::Response::Error(v::Error::Unavailable)
            ));
            key
        });
        drop(worker);
        let store = wudo_store::Store::open(dir.path()).unwrap();
        assert!(!store.credential_id_exists(&key).unwrap());
        assert_eq!(store.user_by_name("alice").unwrap().is_none(), reset);
    }
}

#[test]
fn shutdown_discards_late_verification_but_lost_reply_alone_does_not() {
    for shutdown in [true, false] {
        let (dir, worker) = setup();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let key = rt.block_on(async {
            let client = worker.client();
            init(client.clone()).await;
            let (id, begin, _) = open(client.clone(), v::Mode::Insecure).await;
            let (payload, key) = signed_finish(client.clone(), &begin).await;
            let (started, release) = worker.pause_next_verification();
            let cloned = client.clone();
            let running = tokio::spawn(async move {
                cloned
                    .enrollment(
                        v::Endpoint::Web,
                        payload,
                        std::time::Instant::now() + Duration::from_secs(5),
                    )
                    .await
            });
            tokio::time::timeout(Duration::from_secs(2), started)
                .await
                .unwrap()
                .unwrap();
            running.abort();
            assert!(running.await.is_err());
            if shutdown {
                worker.shutdown();
            }
            release.send(()).unwrap();
            if !shutdown {
                let inspect = v::Request::EnrollmentInspect(v::EnrollmentRef { enrollment_id: id });
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        let reply = call(client.clone(), &inspect, v::Endpoint::Admin).await;
                        if matches!(
                            v::decode_response(&reply, &inspect, v::Endpoint::Admin).unwrap(),
                            v::Response::Error(v::Error::Unavailable)
                        ) {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await
                .unwrap();
            }
            key
        });
        drop(worker);
        let store = wudo_store::Store::open(dir.path()).unwrap();
        assert_eq!(store.credential_id_exists(&key).unwrap(), !shutdown);
    }
}
