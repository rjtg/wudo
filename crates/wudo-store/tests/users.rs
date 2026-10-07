use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};
use wudo_store::{Error, MAX_USERS, Store, UserId};

fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[test]
fn durable_users_explicit_initialization_and_lookup() {
    let dir = directory();
    assert!(Store::open(dir.path()).is_err());
    assert!(!dir.path().join("identity.sqlite3").exists());
    let mut store = Store::initialize(dir.path()).unwrap();
    assert!(matches!(
        Store::initialize(dir.path()),
        Err(Error::Conflict)
    ));
    let alice = store.create_user("alice", "Alice’s passkeys").unwrap();
    assert!(UserId::from_bytes(*alice.id.as_bytes()).is_ok());
    assert!(store.user_by_id(alice.id).unwrap() == Some(alice.clone()));
    assert!(store.user_by_name("absent").unwrap().is_none());
    assert!(matches!(
        store.create_user("alice", "Replacement"),
        Err(Error::Conflict)
    ));
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    assert!(store.user_by_name("alice").unwrap() == Some(alice));
}

#[test]
fn bounds_and_sql_values() {
    let dir = directory();
    let mut store = Store::initialize(dir.path()).unwrap();
    for name in [
        "",
        "Alice",
        "a..b",
        "a-",
        "../root",
        "a';DROP TABLE users;--",
    ] {
        assert!(matches!(
            store.create_user(name, "label"),
            Err(Error::InvalidInput)
        ));
    }
    for label in ["".to_owned(), "x".repeat(129), "CANARY\n".into()] {
        assert!(matches!(
            store.create_user("alice", &label),
            Err(Error::InvalidInput)
        ));
    }
    assert!(matches!(
        store.create_user(&"x".repeat(65), "x"),
        Err(Error::InvalidInput)
    ));
    let name = "x".repeat(64);
    store.create_user(&name, &"x".repeat(128)).unwrap();
    let label = "'); DROP TABLE users; --";
    store.create_user("literal", label).unwrap();
    assert_eq!(store.user_by_name("literal").unwrap().unwrap().label, label);
    for i in 2..MAX_USERS {
        store.create_user(&format!("user{i}"), "User").unwrap();
    }
    assert!(matches!(
        store.create_user("overflow", "User"),
        Err(Error::Capacity)
    ));
    drop(store);
    assert!(Store::open(dir.path()).is_ok());
    assert_eq!(format!("{:?}", Error::InvalidInput), "InvalidInput");
}

#[test]
fn invalid_schema_and_records_fail_closed() {
    for sql in [
        "PRAGMA user_version=999",
        "PRAGMA application_id=0",
        "CREATE TABLE extra(x)",
        "CREATE TRIGGER extra AFTER INSERT ON users BEGIN DELETE FROM users; END",
        "INSERT INTO users VALUES (zeroblob(16),'alice','Alice')",
        "INSERT INTO users VALUES (X'00000000000040008000000000000000','INVALID','Alice')",
    ] {
        let dir = directory();
        drop(Store::initialize(dir.path()).unwrap());
        let c = rusqlite::Connection::open(dir.path().join("identity.sqlite3")).unwrap();
        c.execute_batch(sql).unwrap();
        drop(c);
        assert!(Store::open(dir.path()).is_err());
    }
    let dir = directory();
    drop(Store::initialize(dir.path()).unwrap());
    fs::write(
        dir.path().join("identity.sqlite3"),
        b"CANARY invalid database",
    )
    .unwrap();
    assert!(Store::open(dir.path()).is_err());
    fs::write(dir.path().join("identity.sqlite3"), b"").unwrap();
    assert!(Store::open(dir.path()).is_err());
    assert!(matches!(
        Store::initialize(dir.path()),
        Err(Error::Conflict)
    ));
}

#[test]
fn unsafe_files_and_sidecars_are_rejected() {
    for side in [
        "identity.sqlite3",
        "identity.sqlite3-journal",
        "identity.sqlite3-wal",
        "identity.sqlite3-shm",
    ] {
        let dir = directory();
        let other = directory();
        fs::write(other.path().join("target"), "untouched").unwrap();
        if side != "identity.sqlite3" {
            drop(Store::initialize(dir.path()).unwrap());
        }
        symlink(other.path().join("target"), dir.path().join(side)).unwrap();
        assert!(Store::open(dir.path()).is_err());
        assert!(Store::initialize(dir.path()).is_err());
        assert_eq!(fs::read(other.path().join("target")).unwrap(), b"untouched");
    }
    let dir = directory();
    drop(Store::initialize(dir.path()).unwrap());
    let db = dir.path().join("identity.sqlite3");
    fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Store::open(dir.path()).is_err());
    fs::set_permissions(&db, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&db, dir.path().join("alias")).unwrap();
    assert!(Store::open(dir.path()).is_err());
    let dir = directory();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Store::initialize(dir.path()).is_err());
}

#[test]
fn transactions_rollback_and_competing_creates_keep_unique_names() {
    let dir = directory();
    drop(Store::initialize(dir.path()).unwrap());
    let mut handles = Vec::new();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    for _ in 0..2 {
        let path = dir.path().to_path_buf();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let mut store = Store::open(&path).unwrap();
            barrier.wait();
            store
                .create_user("alice", "Alice")
                .map(|u| *u.id.as_bytes())
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Error::Conflict)))
            .count(),
        1
    );
    let mut c = rusqlite::Connection::open(dir.path().join("identity.sqlite3")).unwrap();
    {
        let tx = c.transaction().unwrap();
        tx.execute("DELETE FROM users", []).unwrap();
        // Dropping the transaction must roll it back.
    }
    drop(c);
    assert!(
        Store::open(dir.path())
            .unwrap()
            .user_by_name("alice")
            .unwrap()
            .is_some()
    );
}

#[test]
fn storage_failure_requires_reopen_without_claiming_success() {
    let dir = directory();
    let mut store = Store::initialize(dir.path()).unwrap();
    store.create_user("existing", "Existing").unwrap();
    let c = rusqlite::Connection::open(dir.path().join("identity.sqlite3")).unwrap();
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(matches!(
        store.create_user("blocked", "Blocked"),
        Err(Error::Unavailable)
    ));
    c.execute_batch("ROLLBACK").unwrap();
    assert!(matches!(
        store.create_user("later", "Later"),
        Err(Error::Unavailable)
    ));
    assert!(matches!(
        store.user_by_name("existing"),
        Err(Error::Unavailable)
    ));
    drop(store);
    let mut store = Store::open(dir.path()).unwrap();
    assert!(store.user_by_name("blocked").unwrap().is_none());
    assert!(store.user_by_name("existing").unwrap().is_some());
    store.create_user("later", "Later").unwrap();
}
