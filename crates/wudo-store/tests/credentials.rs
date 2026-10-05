use std::{fs, os::unix::fs::PermissionsExt};
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
use webauthn_rs::prelude::*;
use wudo_store::{Error, Store, UserId};

fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn verifier() -> Webauthn {
    WebauthnBuilder::new(
        "wudo.example.test",
        &Url::parse("https://wudo.example.test").unwrap(),
    )
    .unwrap()
    .build()
    .unwrap()
}
fn credential(server: &Webauthn, user: UserId) -> (WebauthnAuthenticator<SoftPasskey>, Passkey) {
    let mut client = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (options, state) = server
        .start_passkey_registration(Uuid::from_bytes(*user.as_bytes()), "alice", "Alice", None)
        .unwrap();
    let response = client
        .do_registration(Url::parse("https://wudo.example.test").unwrap(), options)
        .unwrap();
    let key = server
        .finish_passkey_registration(&response, &state)
        .unwrap();
    (client, key)
}
#[test]
fn v1_requires_explicit_upgrade_and_preserves_users() {
    let dir = directory();
    let db = dir.path().join("identity.sqlite3");
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch(include_str!("../migrations/001_users.sql"))
        .unwrap();
    c.execute_batch("PRAGMA user_version=1").unwrap();
    let id = [0x40, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];
    c.execute(
        "INSERT INTO users VALUES(?1,'alice','Alice')",
        [id.as_slice()],
    )
    .unwrap();
    drop(c);
    fs::set_permissions(db, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        Store::open(dir.path()),
        Err(Error::UpgradeRequired)
    ));
    let old = Store::open_for_upgrade(dir.path()).unwrap();
    assert!(old.needs_upgrade().unwrap());
    assert!(matches!(old.user_by_name("alice"), Err(Error::Unavailable)));
    drop(old);
    assert_eq!(Store::schema_version(dir.path()).unwrap(), 1);
    let store = Store::upgrade(dir.path()).unwrap();
    assert!(!store.needs_upgrade().unwrap());
    assert!(store.user_by_name("alice").unwrap().is_some());
    drop(store);
    assert_eq!(Store::schema_version(dir.path()).unwrap(), 3);
    assert!(Store::upgrade(dir.path()).is_ok());
}
#[test]
fn verified_credential_survives_restart_and_revocation_is_terminal() {
    let dir = directory();
    let server = verifier();
    let mut store = Store::initialize(dir.path()).unwrap();
    let user = store.create_user("alice", "Alice").unwrap();
    let other = store.create_user("bob", "Bob").unwrap();
    let (mut client, key) = credential(&server, user.id);
    store.activate_credential(user.id, &key).unwrap();
    assert!(matches!(
        store.configure_installation("https://wudo.example.test"),
        Err(Error::Conflict)
    ));

    assert!(matches!(
        store.activate_credential(other.id, &key),
        Err(Error::Conflict)
    ));
    assert!(
        store
            .credential_for_authentication(other.id, key.cred_id().as_ref())
            .unwrap()
            .is_none()
    );
    drop(store);
    let mut store = Store::open(dir.path()).unwrap();
    let restored = store
        .credential_for_authentication(user.id, key.cred_id().as_ref())
        .unwrap()
        .unwrap();
    let (options, state) = server.start_passkey_authentication(&[restored]).unwrap();
    let response = client
        .do_authentication(Url::parse("https://wudo.example.test").unwrap(), options)
        .unwrap();
    assert!(
        server
            .finish_passkey_authentication(&response, &state)
            .is_ok()
    );
    assert!(store.revoke_credential(key.cred_id().as_ref()).unwrap());
    assert!(!store.revoke_credential(key.cred_id().as_ref()).unwrap());
    assert!(!store.revoke_credential(b"missing").unwrap());
    drop(store);
    let mut store = Store::open(dir.path()).unwrap();
    assert!(
        store
            .credential_for_authentication(user.id, key.cred_id().as_ref())
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        store.activate_credential(user.id, &key),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        store.activate_credential(other.id, &key),
        Err(Error::Conflict)
    ));
}
#[test]
fn capacity_and_missing_owner_are_rejected() {
    let dir = directory();
    let server = verifier();
    let mut store = Store::initialize(dir.path()).unwrap();
    let user = store.create_user("alice", "Alice").unwrap();
    let mut first = None;
    for _ in 0..16 {
        let (_, key) = credential(&server, user.id);
        store.activate_credential(user.id, &key).unwrap();
        first.get_or_insert(key);
    }
    let (_, extra) = credential(&server, user.id);
    assert!(matches!(
        store.activate_credential(user.id, &extra),
        Err(Error::Capacity)
    ));
    let mut missing = *user.id.as_bytes();
    missing[0] ^= 1;
    assert!(matches!(
        store.activate_credential(UserId::from_bytes(missing).unwrap(), &extra),
        Err(Error::InvalidInput)
    ));
    store
        .revoke_credential(first.unwrap().cred_id().as_ref())
        .unwrap();
    store.activate_credential(user.id, &extra).unwrap();
    assert!(matches!(
        store.credential_for_authentication(user.id, &[]),
        Err(Error::InvalidInput)
    ));
    assert!(matches!(
        store.revoke_credential(&[1; 1024]),
        Err(Error::InvalidInput)
    ));
}
#[test]
fn malformed_or_incompatible_records_fail_closed() {
    for mutation in 0..5 {
        let dir = directory();
        let mut store = Store::initialize(dir.path()).unwrap();
        let user = store.create_user("alice", "Alice").unwrap();
        let (_, key) = credential(&verifier(), user.id);
        store.activate_credential(user.id, &key).unwrap();
        drop(store);
        let c = rusqlite::Connection::open(dir.path().join("identity.sqlite3")).unwrap();
        c.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON")
            .unwrap();
        match mutation {
            0 => {
                c.execute("UPDATE credentials SET format=2", []).unwrap();
            }
            1 => {
                c.execute("UPDATE credentials SET id=X'01'", []).unwrap();
            }
            2 => {
                c.execute("UPDATE credentials SET user_id=zeroblob(16)", [])
                    .unwrap();
            }
            3 => {
                c.execute("UPDATE credentials SET record=?1", [b"CANARY".as_slice()])
                    .unwrap();
            }
            _ => {
                let mut value = serde_json::to_value(&key).unwrap();
                value
                    .as_object_mut()
                    .unwrap()
                    .insert("unknown".into(), true.into());
                c.execute(
                    "UPDATE credentials SET record=?1",
                    [serde_json::to_vec(&value).unwrap()],
                )
                .unwrap();
            }
        }
        drop(c);
        assert!(Store::open(dir.path()).is_err());
        assert!(Store::upgrade(dir.path()).is_err());
    }
}

#[test]
fn retained_revocations_count_toward_global_capacity() {
    let dir = directory();
    let server = verifier();
    let mut store = Store::initialize(dir.path()).unwrap();
    let user = store.create_user("alice", "Alice").unwrap();
    for _ in 0..wudo_store::MAX_CREDENTIALS {
        let (_, key) = credential(&server, user.id);
        store.activate_credential(user.id, &key).unwrap();
        store.revoke_credential(key.cred_id().as_ref()).unwrap();
    }
    drop(store);
    let mut store = Store::open(dir.path()).unwrap();
    let (_, extra) = credential(&server, user.id);
    assert!(matches!(
        store.activate_credential(user.id, &extra),
        Err(Error::Capacity)
    ));
}

#[test]
fn explicit_reset_removes_active_and_revoked_credentials() {
    let dir = directory();
    let mut store = Store::initialize(dir.path()).unwrap();
    store
        .configure_installation("https://wudo.example.test")
        .unwrap();
    let user = store.create_user("alice", "Alice").unwrap();
    let (_, active) = credential(&verifier(), user.id);
    let (_, revoked) = credential(&verifier(), user.id);
    store.activate_credential(user.id, &active).unwrap();
    store.activate_credential(user.id, &revoked).unwrap();
    store.revoke_credential(revoked.cred_id().as_ref()).unwrap();
    store
        .reset_installation("https://new.example.test")
        .unwrap();
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    assert!(store.user_by_id(user.id).unwrap().is_none());
    assert!(
        !store
            .credential_id_exists(active.cred_id().as_ref())
            .unwrap()
    );
    assert!(
        !store
            .credential_id_exists(revoked.cred_id().as_ref())
            .unwrap()
    );
}

#[test]
fn administrative_credential_pages_and_owned_terminal_revocation() {
    let dir = directory();
    let mut s = Store::initialize(dir.path()).unwrap();
    let a = s.create_user("alice", "Alice").unwrap();
    let b = s.create_user("bob", "Bob").unwrap();
    let server = verifier();
    let mut keys = Vec::new();
    for _ in 0..18 {
        let (_, key) = credential(&server, a.id);
        s.activate_credential(a.id, &key).unwrap();
        assert!(
            s.revoke_owned_credential(b.id, key.cred_id().as_ref())
                .unwrap()
                .is_none()
        );
        assert!(
            !s.inspect_credential(a.id, key.cred_id().as_ref())
                .unwrap()
                .unwrap()
                .revoked
        );
        assert!(
            s.revoke_owned_credential(a.id, key.cred_id().as_ref())
                .unwrap()
                .unwrap()
                .revoked
        );
        keys.push(key);
    }
    let (_, active) = credential(&server, a.id);
    s.activate_credential(a.id, &active).unwrap();
    let first = s.list_credentials(a.id, None).unwrap().unwrap();
    assert_eq!(first.items.len(), 16);
    let second = s
        .list_credentials(a.id, first.next_after.as_deref())
        .unwrap()
        .unwrap();
    assert_eq!(second.items.len(), 3);
    assert!(second.next_after.is_none());
    let mut ids: Vec<_> = keys.iter().map(|k| k.cred_id().as_ref().to_vec()).collect();
    ids.push(active.cred_id().as_ref().to_vec());
    ids.sort();
    assert_eq!(
        first
            .items
            .iter()
            .chain(&second.items)
            .map(|c| c.id.clone())
            .collect::<Vec<_>>(),
        ids
    );
    assert!(
        s.list_credentials(b.id, None)
            .unwrap()
            .unwrap()
            .items
            .is_empty()
    );
    assert!(
        s.inspect_credential(b.id, active.cred_id().as_ref())
            .unwrap()
            .is_none()
    );
    assert!(
        s.revoke_owned_credential(a.id, b"absent")
            .unwrap()
            .is_none()
    );
    assert!(
        s.revoke_owned_credential(a.id, keys[0].cred_id().as_ref())
            .unwrap()
            .unwrap()
            .revoked
    );
    assert!(
        s.credential_for_authentication(a.id, active.cred_id().as_ref())
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        s.activate_credential(a.id, &keys[0]),
        Err(Error::Conflict)
    ));
    drop(s);
    let s = Store::open(dir.path()).unwrap();
    assert!(
        s.inspect_credential(a.id, keys[0].cred_id().as_ref())
            .unwrap()
            .unwrap()
            .revoked
    );
    assert!(
        s.credential_for_authentication(a.id, keys[0].cred_id().as_ref())
            .unwrap()
            .is_none()
    );
}

#[test]
fn owned_revocation_failure_rolls_back_and_requires_reopen() {
    let dir = directory();
    let mut s = Store::initialize(dir.path()).unwrap();
    let u = s.create_user("alice", "Alice").unwrap();
    let (_, key) = credential(&verifier(), u.id);
    s.activate_credential(u.id, &key).unwrap();
    let db = rusqlite::Connection::open(dir.path().join("identity.sqlite3")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_revoke AFTER UPDATE OF revoked ON credentials BEGIN SELECT RAISE(ABORT,'injected'); END").unwrap();
    assert!(
        s.revoke_owned_credential(u.id, key.cred_id().as_ref())
            .is_err()
    );
    assert!(matches!(
        s.inspect_credential(u.id, key.cred_id().as_ref()),
        Err(Error::Unavailable)
    ));
    db.execute_batch("DROP TRIGGER fail_revoke").unwrap();
    drop(db);
    drop(s);
    let s = Store::open(dir.path()).unwrap();
    assert!(
        !s.inspect_credential(u.id, key.cred_id().as_ref())
            .unwrap()
            .unwrap()
            .revoked
    );
}
