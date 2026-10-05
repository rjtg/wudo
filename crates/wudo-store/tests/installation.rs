use std::{fs, os::unix::fs::PermissionsExt};
use wudo_store::{Error, Store};
fn dir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    d
}
#[test]
fn configure_once_persists_and_never_overwrites() {
    let d = dir();
    let mut s = Store::initialize(d.path()).unwrap();
    let user = s.create_user("alice", "Alice").unwrap();
    assert!(s.installation_origin().unwrap().is_none());
    assert!(matches!(
        s.configure_installation("http://pi.lan"),
        Err(Error::InvalidInput)
    ));
    s.configure_installation("https://pi.lan:443/").unwrap();
    for value in ["https://pi.lan", "https://other.lan"] {
        assert!(matches!(
            s.configure_installation(value),
            Err(Error::Conflict)
        ));
    }
    drop(s);
    let s = Store::open(d.path()).unwrap();
    let origin = s.installation_origin().unwrap().unwrap();
    assert_eq!(origin.as_str(), "https://pi.lan");
    assert_eq!(origin.rp_id(), "pi.lan");
    assert!(s.user_by_id(user.id).unwrap().is_some());
}
#[test]
fn v2_upgrade_preserves_users_and_requires_explicit_setup() {
    let d = dir();
    let db = d.path().join("identity.sqlite3");
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch(include_str!("../migrations/001_users.sql"))
        .unwrap();
    c.execute_batch(include_str!("../migrations/002_credentials.sql"))
        .unwrap();
    c.execute_batch("PRAGMA user_version=2; INSERT INTO users VALUES(X'00000000000040008000000000000000','alice','Alice')").unwrap();
    drop(c);
    fs::set_permissions(&db, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(Store::open(d.path()), Err(Error::UpgradeRequired)));
    let mut s = Store::upgrade(d.path()).unwrap();
    assert!(s.installation_origin().unwrap().is_none());
    assert!(s.user_by_name("alice").unwrap().is_some());
    s.configure_installation("https://pi.lan").unwrap();
}
#[test]
fn persisted_settings_fail_closed_when_corrupt() {
    for value in [
        "http://pi.lan",
        "https://pi.lan/",
        "https://pi.lan:443",
        "https://other.lan/path",
    ] {
        let d = dir();
        let mut s = Store::initialize(d.path()).unwrap();
        s.configure_installation("https://pi.lan").unwrap();
        drop(s);
        let c = rusqlite::Connection::open(d.path().join("identity.sqlite3")).unwrap();
        c.execute("UPDATE installation SET origin=?1", [value])
            .unwrap();
        drop(c);
        assert!(Store::open(d.path()).is_err());
        assert!(Store::upgrade(d.path()).is_err());
    }
}

#[test]
fn reset_is_atomic_and_preserves_old_state_on_failure() {
    let d = dir();
    let mut s = Store::initialize(d.path()).unwrap();
    s.configure_installation("https://old.example").unwrap();
    let user = s.create_user("alice", "Alice").unwrap();
    assert!(matches!(
        s.reset_installation("http://bad.example"),
        Err(Error::InvalidInput)
    ));
    assert!(s.user_by_id(user.id).unwrap().is_some());
    let db = rusqlite::Connection::open(d.path().join("identity.sqlite3")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_reset BEFORE INSERT ON installation BEGIN SELECT RAISE(ABORT,'synthetic'); END;").unwrap();
    assert!(matches!(
        s.reset_installation("https://new.example"),
        Err(Error::Unavailable)
    ));
    db.execute_batch("DROP TRIGGER fail_reset").unwrap();
    drop(db);
    drop(s);
    let mut s = Store::open(d.path()).unwrap();
    assert!(s.user_by_id(user.id).unwrap().is_some());
    assert_eq!(
        s.installation_origin().unwrap().unwrap().as_str(),
        "https://old.example"
    );
    s.reset_installation("https://new.example").unwrap();
    drop(s);
    let s = Store::open(d.path()).unwrap();
    assert!(s.user_by_id(user.id).unwrap().is_none());
    assert_eq!(
        s.installation_origin().unwrap().unwrap().as_str(),
        "https://new.example"
    );
}
