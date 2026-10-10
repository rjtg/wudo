use super::*;
use std::os::unix::fs::PermissionsExt;
use webauthn_authenticator_rs::{AuthenticatorBackendHashedClientData, softpasskey::SoftPasskey};
const ORIGIN: &str = "https://wudo.example.test";
fn bytes(q: &wire::Request<'_>) -> Vec<u8> {
    let mut b = vec![0; wire::MAX_PAYLOAD];
    let n = wire::encode_request(&mut b, q, wire::Endpoint::Web).unwrap();
    b.truncate(n);
    b
}
struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    engine: Viewing,
    authenticator: SoftPasskey,
    user: UserId,
    credential: Vec<u8>,
}
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut store = Store::initialize(dir.path()).unwrap();
    store.configure_installation(ORIGIN).unwrap();
    let user = store.create_user("alice", "Alice").unwrap().id;
    let engine = Viewing::new(&store, 300).unwrap();
    let mut authenticator = SoftPasskey::new(true);
    let (options, state) = engine
        .verifier
        .start_passkey_registration(Uuid::from_bytes(*user.as_bytes()), "alice", "Alice", None)
        .unwrap();
    let data=serde_json::to_vec(&serde_json::json!({"type":"webauthn.create","challenge":options.public_key.challenge,"origin":ORIGIN})).unwrap();
    let mut response = authenticator
        .perform_register(
            openssl::sha::sha256(&data).to_vec(),
            options.public_key,
            120000,
        )
        .unwrap();
    response.response.client_data_json = data.into();
    let passkey = engine
        .verifier
        .finish_passkey_registration(&response, &state)
        .unwrap();
    store.activate_credential(user, &passkey).unwrap();
    Fixture {
        _dir: dir,
        store,
        engine,
        authenticator,
        user,
        credential: passkey.cred_id().as_ref().to_vec(),
    }
}
fn begin(f: &mut Fixture, now: Instant) -> Vec<u8> {
    let q = wire::Request::ViewBegin(wire::ViewBegin {
        user_name: wire::Name("alice"),
    });
    f.engine.begin(&bytes(&q), &f.store, now).unwrap()
}
fn finish(f: &mut Fixture, challenge: &[u8], origin: &str) -> Vec<u8> {
    let q = wire::Request::ViewBegin(wire::ViewBegin {
        user_name: wire::Name("alice"),
    });
    let wire::Response::ActionChallenge(c) =
        wire::decode_response(challenge, &q, wire::Endpoint::Web).unwrap()
    else {
        panic!("challenge")
    };
    let options:RequestChallengeResponse=serde_json::from_value(serde_json::json!({"publicKey":{
        "challenge":Base64UrlSafeData::from(c.options.challenge.0.to_vec()),"rpId":c.options.rp_id.0,"timeout":120000,"userVerification":"required",
        "allowCredentials":c.options.allow_credentials.0.iter().map(|id|serde_json::json!({"type":"public-key","id":Base64UrlSafeData::from(id.0.to_vec())})).collect::<Vec<_>>()
    }})).unwrap();
    let data=serde_json::to_vec(&serde_json::json!({"type":"webauthn.get","challenge":options.public_key.challenge,"origin":origin})).unwrap();
    let response = f
        .authenticator
        .perform_auth(
            openssl::sha::sha256(&data).to_vec(),
            options.public_key,
            120000,
        )
        .unwrap();
    bytes(&wire::Request::ViewFinish(wire::ActionFinish {
        ceremony_id: c.ceremony_id,
        credential_id: wire::Blob(response.raw_id.as_ref()),
        client_data: wire::Blob(&data),
        authenticator_data: wire::Blob(response.response.authenticator_data.as_ref()),
        signature: wire::Blob(response.response.signature.as_ref()),
        user_handle: Some(wire::UserId(*f.user.as_bytes())),
    }))
}
fn login(f: &mut Fixture, now: Instant) -> wire::ViewSession {
    let c = begin(f, now);
    let b = finish(f, &c, ORIGIN);
    let job = f.engine.take_finish(&b, now).unwrap();
    assert!(matches!(
        f.engine.take_finish(&b, now),
        Err(Error::Unavailable)
    ));
    f.engine.complete(job.run(), &mut f.store, now).unwrap()
}
fn poll(f: &mut Fixture, token: wire::ViewToken, now: Instant) -> Result<Vec<u8>> {
    f.engine.actions(
        &bytes(&wire::Request::ViewActions(wire::ViewActions {
            token,
            after: None,
        })),
        &f.store,
        &wudo_core::config::Config::empty(),
        now,
    )
}
#[test]
fn signed_login_replay_throttling_expiry_and_revocation() {
    let mut f = fixture();
    let now = Instant::now();
    let session = login(&mut f, now);
    assert!(poll(&mut f, wire::ViewToken([0; 32]), now).is_err());
    assert!(poll(&mut f, session.token, now).is_ok());
    assert!(matches!(
        poll(&mut f, session.token, now + Duration::from_secs(1)),
        Err(Error::Busy)
    ));
    assert!(poll(&mut f, session.token, now + Duration::from_secs(2)).is_ok());
    assert!(matches!(
        poll(&mut f, session.token, now + Duration::from_secs(300)),
        Err(Error::Unavailable)
    ));
    let session = login(&mut f, now + Duration::from_secs(301));
    f.store.revoke_credential(&f.credential).unwrap();
    assert!(matches!(
        poll(&mut f, session.token, now + Duration::from_secs(302)),
        Err(Error::Unavailable)
    ));
}
#[test]
fn wrong_purpose_origin_reset_and_expiry_never_issue_a_session() {
    let mut f = fixture();
    let now = Instant::now();
    let c = begin(&mut f, now);
    let b = finish(&mut f, &c, ORIGIN);
    let wire::Request::ViewFinish(v) = wire::decode_request(&b, wire::Endpoint::Web).unwrap()
    else {
        panic!("finish")
    };
    assert!(matches!(
        f.engine
            .take_finish(&bytes(&wire::Request::ActionFinish(v)), now),
        Err(Error::UnsupportedOperation)
    ));
    let job = f.engine.take_finish(&b, now).unwrap();
    f.engine.invalidate();
    assert!(matches!(
        f.engine.complete(job.run(), &mut f.store, now),
        Err(Error::Unavailable)
    ));
    let c = begin(&mut f, now);
    let b = finish(&mut f, &c, "https://wrong.example.test");
    let job = f.engine.take_finish(&b, now).unwrap();
    assert!(matches!(
        f.engine.complete(job.run(), &mut f.store, now),
        Err(Error::VerificationFailed)
    ));
    let c = begin(&mut f, now);
    let b = finish(&mut f, &c, ORIGIN);
    let job = f.engine.take_finish(&b, now).unwrap();
    assert!(matches!(
        f.engine.complete(job.run(), &mut f.store, now + CEREMONY),
        Err(Error::Unavailable)
    ));
    assert!(f.engine.sessions.is_empty());
}
#[test]
fn pending_reservations_and_lost_replies_do_not_evict_sessions() {
    let mut f = fixture();
    let now = Instant::now();
    begin(&mut f, now);
    begin(&mut f, now);
    let q = bytes(&wire::Request::ViewBegin(wire::ViewBegin {
        user_name: wire::Name("alice"),
    }));
    assert!(matches!(
        f.engine.begin(&q, &f.store, now),
        Err(Error::Unavailable)
    ));
    let now = now + CEREMONY;
    for _ in 0..4 {
        login(&mut f, now);
    }
    assert!(matches!(
        f.engine.begin(&q, &f.store, now),
        Err(Error::Unavailable)
    ));
    assert_eq!(f.engine.sessions.len(), 4);
    assert!(
        f.engine
            .begin(&q, &f.store, now + Duration::from_secs(300))
            .is_ok()
    );
}
#[test]
fn revocation_between_verification_and_commit_fails_closed() {
    let mut f = fixture();
    let now = Instant::now();
    let c = begin(&mut f, now);
    let b = finish(&mut f, &c, ORIGIN);
    let result = f.engine.take_finish(&b, now).unwrap().run();
    f.store.revoke_credential(&f.credential).unwrap();
    assert!(matches!(
        f.engine.complete(result, &mut f.store, now),
        Err(Error::Unavailable)
    ));
    assert!(f.engine.sessions.is_empty());
}

#[test]
fn current_grants_filter_pages_and_reads_never_enable_execution() {
    let mut f = fixture();
    let now = Instant::now();
    let config = wudo_core::config::Config::parse(include_bytes!(
        "../../../../examples/paperless.v2.actions.toml"
    ))
    .unwrap();
    f.store.reconcile_actions(&config).unwrap();
    let id = config.actions().keys().next().unwrap().as_str();
    f.store.set_grant(f.user, id, true).unwrap();
    let session = login(&mut f, now);
    let q = wire::Request::ViewActions(wire::ViewActions {
        token: session.token,
        after: None,
    });
    let response = f
        .engine
        .actions(&bytes(&q), &f.store, &config, now)
        .unwrap();
    let wire::Response::ViewPage(page) =
        wire::decode_response(&response, &q, wire::Endpoint::Web).unwrap()
    else {
        panic!("page")
    };
    assert_eq!(page.actions.0.len(), 1);
    assert_eq!(page.actions.0[0].action_id.0, id);
    assert_ne!(
        page.actions.0[0].availability,
        wire::Availability::Available
    );
    f.store.set_grant(f.user, id, false).unwrap();
    let response = f
        .engine
        .actions(&bytes(&q), &f.store, &config, now + Duration::from_secs(2))
        .unwrap();
    let wire::Response::ViewPage(page) =
        wire::decode_response(&response, &q, wire::Endpoint::Web).unwrap()
    else {
        panic!("page")
    };
    assert!(page.actions.0.is_empty());
}

#[test]
fn stale_snapshot_and_invalid_signature_cannot_create_sessions() {
    let mut f = fixture();
    let now = Instant::now();
    let a = begin(&mut f, now);
    let b = begin(&mut f, now);
    let a = finish(&mut f, &a, ORIGIN);
    let b = finish(&mut f, &b, ORIGIN);
    let a = f.engine.take_finish(&a, now).unwrap().run();
    let b = f.engine.take_finish(&b, now).unwrap().run();
    f.engine.complete(a, &mut f.store, now).unwrap();
    assert!(matches!(
        f.engine.complete(b, &mut f.store, now),
        Err(Error::Unavailable)
    ));
    let c = begin(&mut f, now);
    let b = finish(&mut f, &c, ORIGIN);
    let wire::Request::ViewFinish(mut v) = wire::decode_request(&b, wire::Endpoint::Web).unwrap()
    else {
        panic!("finish")
    };
    v.signature = wire::Blob(b"invalid signature");
    let b = bytes(&wire::Request::ViewFinish(v));
    let result = f.engine.take_finish(&b, now).unwrap().run();
    assert!(matches!(
        f.engine.complete(result, &mut f.store, now),
        Err(Error::VerificationFailed)
    ));
    assert_eq!(f.engine.sessions.len(), 1);
}
