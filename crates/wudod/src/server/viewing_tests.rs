use super::*;
use crate::storage::{Client, Worker};
use std::os::unix::fs::PermissionsExt;
use webauthn_authenticator_rs::{AuthenticatorBackendHashedClientData, softpasskey::SoftPasskey};
use webauthn_rs::prelude::*;
use wudo_protocol::v2 as v;
const ORIGIN: &str = "https://wudo.example.test";
fn encode(q: &v::Request<'_>, ep: v::Endpoint) -> Vec<u8> {
    let mut b = vec![0; v::MAX_PAYLOAD];
    let n = v::encode_request(&mut b, q, ep).unwrap();
    b.truncate(n);
    b
}
async fn raw(client: Client, ep: v::Endpoint, payload: Vec<u8>) -> Vec<u8> {
    let (mut peer, server) = UnixStream::pair().unwrap();
    let task = tokio::spawn(exchange_with_store(
        server,
        ep,
        Some(client),
        Instant::now() + Duration::from_secs(5),
    ));
    peer.write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .unwrap();
    peer.write_all(&payload).await.unwrap();
    peer.shutdown().await.unwrap();
    let mut reply = vec![];
    peer.read_to_end(&mut reply).await.unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(
        v::payload_len(reply[..4].try_into().unwrap()).unwrap() + 4,
        reply.len()
    );
    reply[4..].to_vec()
}
async fn call(c: Client, q: &v::Request<'_>, ep: v::Endpoint) -> Vec<u8> {
    raw(c, ep, encode(q, ep)).await
}
fn setup() -> (tempfile::TempDir, Worker, SoftPasskey, v::UserId, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut store = wudo_store::Store::initialize(dir.path()).unwrap();
    store.configure_installation(ORIGIN).unwrap();
    let user = store.create_user("alice", "Alice").unwrap();
    let verifier = WebauthnBuilder::new("wudo.example.test", &Url::parse(ORIGIN).unwrap())
        .unwrap()
        .build()
        .unwrap();
    let (options, state) = verifier
        .start_passkey_registration(
            Uuid::from_bytes(*user.id.as_bytes()),
            "alice",
            "Alice",
            None,
        )
        .unwrap();
    let data=serde_json::to_vec(&serde_json::json!({"type":"webauthn.create","challenge":options.public_key.challenge,"origin":ORIGIN})).unwrap();
    let mut authenticator = SoftPasskey::new(true);
    let mut response = authenticator
        .perform_register(
            openssl::sha::sha256(&data).to_vec(),
            options.public_key,
            120000,
        )
        .unwrap();
    response.response.client_data_json = data.into();
    let passkey = verifier
        .finish_passkey_registration(&response, &state)
        .unwrap();
    store.activate_credential(user.id, &passkey).unwrap();
    drop(store);
    let worker = Worker::start(dir.path().into(), None).unwrap();
    (
        dir,
        worker,
        authenticator,
        v::UserId(*user.id.as_bytes()),
        passkey.cred_id().as_ref().to_vec(),
    )
}
async fn login(client: Client, authenticator: &mut SoftPasskey) -> (v::ViewToken, Vec<u8>) {
    let q = v::Request::ViewBegin(v::ViewBegin {
        user_name: v::Name("alice"),
    });
    let reply = call(client.clone(), &q, v::Endpoint::Web).await;
    let v::Response::ActionChallenge(c) = v::decode_response(&reply, &q, v::Endpoint::Web).unwrap()
    else {
        panic!("challenge")
    };
    let options:RequestChallengeResponse=serde_json::from_value(serde_json::json!({"publicKey":{
        "challenge":Base64UrlSafeData::from(c.options.challenge.0.to_vec()),"rpId":c.options.rp_id.0,"timeout":120000,"userVerification":"required",
        "allowCredentials":c.options.allow_credentials.0.iter().map(|id|serde_json::json!({"type":"public-key","id":Base64UrlSafeData::from(id.0.to_vec())})).collect::<Vec<_>>()
    }})).unwrap();
    let data=serde_json::to_vec(&serde_json::json!({"type":"webauthn.get","challenge":options.public_key.challenge,"origin":ORIGIN})).unwrap();
    let response = authenticator
        .perform_auth(
            openssl::sha::sha256(&data).to_vec(),
            options.public_key,
            120000,
        )
        .unwrap();
    let q = v::Request::ViewFinish(v::ActionFinish {
        ceremony_id: c.ceremony_id,
        credential_id: v::Blob(response.raw_id.as_ref()),
        client_data: v::Blob(&data),
        authenticator_data: v::Blob(response.response.authenticator_data.as_ref()),
        signature: v::Blob(response.response.signature.as_ref()),
        user_handle: None,
    });
    let payload = encode(&q, v::Endpoint::Web);
    let reply = raw(client, v::Endpoint::Web, payload.clone()).await;
    let v::Response::ViewSession(s) = v::decode_response(&reply, &q, v::Endpoint::Web).unwrap()
    else {
        panic!("session")
    };
    (s.token, payload)
}
#[tokio::test]
async fn viewing_ipc_is_read_only_revocable_and_restart_scoped() {
    let (dir, worker, mut authenticator, user, credential) = setup();
    let client = worker.client();
    let (token, finish) = login(client.clone(), &mut authenticator).await;
    let response = raw(client.clone(), v::Endpoint::Web, finish.clone()).await;
    assert!(matches!(
        v::decode_response(
            &response,
            &v::decode_request(&finish, v::Endpoint::Web).unwrap(),
            v::Endpoint::Web
        )
        .unwrap(),
        v::Response::Error(v::Error::Unavailable)
    ));
    let q = v::Request::ViewActions(v::ViewActions { token, after: None });
    let reply = call(client.clone(), &q, v::Endpoint::Web).await;
    assert!(matches!(
        v::decode_response(&reply, &q, v::Endpoint::Web).unwrap(),
        v::Response::ViewPage(_)
    ));
    let revoke = v::Request::CredentialRevoke(v::CredentialRef {
        user_id: user,
        credential_id: v::Blob(&credential),
    });
    let reply = call(client.clone(), &revoke, v::Endpoint::Admin).await;
    assert!(matches!(
        v::decode_response(&reply, &revoke, v::Endpoint::Admin).unwrap(),
        v::Response::CredentialRevoked(_)
    ));
    let reply = call(client.clone(), &q, v::Endpoint::Web).await;
    assert!(matches!(
        v::decode_response(&reply, &q, v::Endpoint::Web).unwrap(),
        v::Response::Error(v::Error::Unavailable)
    ));
    drop(client);
    drop(worker);
    let worker = Worker::start(dir.path().into(), None).unwrap();
    let reply = call(worker.client(), &q, v::Endpoint::Web).await;
    assert!(matches!(
        v::decode_response(&reply, &q, v::Endpoint::Web).unwrap(),
        v::Response::Error(v::Error::Unavailable)
    ));
}
#[tokio::test]
async fn root_reset_invalidates_view_tokens_even_at_same_origin() {
    let (_dir, worker, mut authenticator, _, _) = setup();
    let client = worker.client();
    let (token, _) = login(client.clone(), &mut authenticator).await;
    let reset = v::Request::InstallationReset(v::InstallationInitialize {
        origin: v::Text(ORIGIN),
    });
    let reply = call(client.clone(), &reset, v::Endpoint::Admin).await;
    assert!(matches!(
        v::decode_response(&reply, &reset, v::Endpoint::Admin).unwrap(),
        v::Response::StoreReady(_)
    ));
    let q = v::Request::ViewActions(v::ViewActions { token, after: None });
    let reply = call(client, &q, v::Endpoint::Web).await;
    assert!(matches!(
        v::decode_response(&reply, &q, v::Endpoint::Web).unwrap(),
        v::Response::Error(v::Error::Unavailable)
    ));
}
