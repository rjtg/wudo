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
    engine: Actions,
    config: wudo_core::config::Config,
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
    let config = wudo_core::config::Config::parse(include_bytes!(
        "../../../../examples/paperless.v2.actions.toml"
    ))
    .unwrap();
    store.reconcile_actions(&config).unwrap();
    store.set_grant(user, "paperless.stop", true).unwrap();
    let engine = Actions::with_budgets(&store, crate::ceremony_budget::Budgets::default()).unwrap();
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
        config,
        authenticator,
        user,
        credential: passkey.cred_id().as_ref().to_vec(),
    }
}
fn begin(f: &mut Fixture, now: Instant) -> Vec<u8> {
    let q = wire::Request::ActionBegin(wire::ActionBegin {
        user_name: wire::Name("alice"),
        action_id: wire::Name("paperless.stop"),
    });
    f.engine
        .begin(&bytes(&q), &f.store, &f.config, now)
        .unwrap()
}
fn finish(f: &mut Fixture, challenge: &[u8], origin: &str) -> Vec<u8> {
    let q = wire::Request::ActionBegin(wire::ActionBegin {
        user_name: wire::Name("alice"),
        action_id: wire::Name("paperless.stop"),
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
    bytes(&wire::Request::ActionFinish(wire::ActionFinish {
        ceremony_id: c.ceremony_id,
        credential_id: wire::Blob(response.raw_id.as_ref()),
        client_data: wire::Blob(&data),
        authenticator_data: wire::Blob(response.response.authenticator_data.as_ref()),
        signature: wire::Blob(response.response.signature.as_ref()),
        user_handle: Some(wire::UserId(*f.user.as_bytes())),
    }))
}

fn authenticate(f: &mut Fixture, now: Instant) -> Authenticated {
    let c = begin(f, now);
    let b = finish(f, &c, ORIGIN);
    let task = f.engine.take_finish(&b, now).unwrap();
    assert!(matches!(
        f.engine.take_finish(&b, now),
        Err(Error::Unavailable)
    ));
    f.engine.complete(task.run(), &mut f.store, now).unwrap()
}
#[test]
fn genuine_assertion_is_bound_to_user_action_revision_and_original_deadline() {
    let mut f = fixture();
    let now = Instant::now();
    let auth = authenticate(&mut f, now);
    assert!(auth.pending.user == f.user);
    assert_eq!(auth.pending.action, "paperless.stop");
    assert_eq!(auth.pending.deadline, now + CEREMONY);
    assert!(f.engine.validate_admission(&auth, &f.store, now).is_ok());
    assert!(matches!(
        f.engine.validate_admission(&auth, &f.store, now + CEREMONY),
        Err(Error::Unavailable)
    ));
}
#[test]
fn unavailable_actions_never_issue_challenges() {
    let mut f = fixture();
    let now = Instant::now();
    for (user, action) in [
        ("nobody", "paperless.stop"),
        ("alice", "unknown"),
        ("alice", "paperless.start"),
    ] {
        let q = bytes(&wire::Request::ActionBegin(wire::ActionBegin {
            user_name: wire::Name(user),
            action_id: wire::Name(action),
        }));
        assert!(matches!(
            f.engine.begin(&q, &f.store, &f.config, now),
            Err(Error::Unavailable)
        ));
    }
    // Even a grant cannot bypass a secret prerequisite unsupported by this integration.
    f.store.set_grant(f.user, "paperless.start", true).unwrap();
    let q = bytes(&wire::Request::ActionBegin(wire::ActionBegin {
        user_name: wire::Name("alice"),
        action_id: wire::Name("paperless.start"),
    }));
    assert!(matches!(
        f.engine.begin(&q, &f.store, &f.config, now),
        Err(Error::Unavailable)
    ));
    f.store.set_grant(f.user, "paperless.stop", false).unwrap();
    let q = bytes(&wire::Request::ActionBegin(wire::ActionBegin {
        user_name: wire::Name("alice"),
        action_id: wire::Name("paperless.stop"),
    }));
    assert!(matches!(
        f.engine.begin(&q, &f.store, &f.config, now),
        Err(Error::Unavailable)
    ));
    assert!(f.engine.pending.is_empty());
}
#[test]
fn final_admission_rechecks_revocation_revision_reset_and_engine_generation() {
    for mode in 0..5 {
        let mut f = fixture();
        let now = Instant::now();
        let auth = authenticate(&mut f, now);
        match mode {
            0 => {
                f.store.set_grant(f.user, "paperless.stop", false).unwrap();
            }
            1 => {
                f.store.revoke_credential(&f.credential).unwrap();
            }
            2 => {
                let config = wudo_core::config::Config::parse(
                    include_str!("../../../../examples/paperless.v2.actions.toml")
                        .replace("paperless.service", "other.service")
                        .as_bytes(),
                )
                .unwrap();
                f.store.reconcile_actions(&config).unwrap();
                f.store.set_grant(f.user, "paperless.stop", true).unwrap();
            }
            3 => f.engine.invalidate(),
            4 => {
                f.engine =
                    Actions::with_budgets(&f.store, crate::ceremony_budget::Budgets::default())
                        .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            f.engine.admit(
                Ready {
                    auth,
                    prepared: crate::integrations::Prepared::fixture()
                },
                &f.store,
                now
            ),
            Err(Error::Unavailable)
        ));
    }
}
#[test]
fn invalid_assertions_are_consumed_and_purposes_are_isolated() {
    for mode in 0..5 {
        let mut f = fixture();
        let now = Instant::now();
        let c = begin(&mut f, now);
        let b = finish(
            &mut f,
            &c,
            if mode == 0 {
                "https://wrong.example.test"
            } else {
                ORIGIN
            },
        );
        let wire::Request::ActionFinish(mut v) =
            wire::decode_request(&b, wire::Endpoint::Web).unwrap()
        else {
            panic!("finish")
        };
        let view = bytes(&wire::Request::ViewFinish(v.clone()));
        assert!(matches!(
            f.engine.take_finish(&view, now),
            Err(Error::UnsupportedOperation)
        ));
        if mode == 1 {
            v.signature = wire::Blob(b"invalid signature");
        }
        if mode == 2 {
            let mut other = *f.user.as_bytes();
            other[0] ^= 1;
            v.user_handle = Some(wire::UserId(other));
        }
        if mode == 3 {
            v.credential_id = wire::Blob(b"unknown");
        }
        let b = bytes(&wire::Request::ActionFinish(v));
        let task = f.engine.take_finish(&b, now);
        assert!(f.engine.take_finish(&b, now).is_err());
        if mode == 2 || mode == 3 {
            assert!(matches!(task, Err(Error::VerificationFailed)));
        } else {
            let task = task.unwrap();
            if mode == 4 {
                f.engine.invalidate();
            }
            assert!(f.engine.complete(task.run(), &mut f.store, now).is_err());
        }
    }
}
#[test]
fn metadata_commit_rejects_stale_revoked_and_expired_results() {
    for mode in 0..3 {
        let mut f = fixture();
        let now = Instant::now();
        let c = begin(&mut f, now);
        let b = finish(&mut f, &c, ORIGIN);
        let result = f.engine.take_finish(&b, now).unwrap().run();
        if mode == 0 {
            f.store.revoke_credential(&f.credential).unwrap();
        }
        if mode == 1 {
            let _newer = authenticate(&mut f, now);
        }
        let at = if mode == 2 { now + CEREMONY } else { now };
        assert!(matches!(
            f.engine.complete(result, &mut f.store, at),
            Err(Error::Unavailable)
        ));
    }
}
#[test]
fn action_ceremonies_share_capacity_and_hold_it_after_verification() {
    let mut f = fixture();
    let now = Instant::now();
    let auth = authenticate(&mut f, now);
    let shared = f.engine.budgets.clone();
    let other = shared.ceremony(f.user).unwrap();
    assert!(matches!(shared.ceremony(f.user), Err(Error::Busy)));
    drop(auth);
    assert!(shared.ceremony(f.user).is_ok());
    drop(other);
}

#[test]
fn admission_consumes_authority_and_preserves_lease_until_submission_is_dropped() {
    let mut f = fixture();
    let now = Instant::now();
    let auth = authenticate(&mut f, now);
    let admitted = f
        .engine
        .admit(
            Ready {
                auth,
                prepared: crate::integrations::Prepared::fixture(),
            },
            &f.store,
            now,
        )
        .unwrap();
    let other = f.engine.budgets.ceremony(f.user).unwrap();
    f.engine.invalidate();
    f.store.revoke_credential(&f.credential).unwrap();
    // Already admitted authority stays alive; neither mutation retries or rolls it back.
    assert!(f.engine.budgets.ceremony(f.user).is_err());
    drop(admitted); // Never submit the synthetic prepared fixture to a real manager.
    assert!(f.engine.budgets.ceremony(f.user).is_ok());
    drop(other);
}
