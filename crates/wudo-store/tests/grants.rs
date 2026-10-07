use std::os::unix::fs::PermissionsExt;
use wudo_core::config::Config;
use wudo_store::{Error, Store};
fn config(unit: &str, description: &str) -> Config {
    Config::parse(format!("schema_version=1\n[resources]\n[actions.\"paperless.start\"]\ndescription={description:?}\nconfirmation=true\ntimeout_seconds=30\noutput_limit_bytes=0\noperation={{kind='systemd-start',unit={unit:?}}}\n[actions.\"other.stop\"]\ndescription='Other'\nconfirmation=true\ntimeout_seconds=30\noutput_limit_bytes=0\noperation={{kind='systemd-stop',unit='other.service'}}\n").as_bytes()).unwrap()
}
fn setup() -> (tempfile::TempDir, Store) {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let s = Store::initialize(d.path()).unwrap();
    (d, s)
}
#[test]
fn revisions_grants_restart_changes_removal_reset() {
    let (dir, mut s) = setup();
    s.configure_installation("https://pi.lan").unwrap();
    let user = s.create_user("alice", "Alice").unwrap().id;
    s.reconcile_actions(&config("paperless.service", "Paperless"))
        .unwrap();
    let first = s.set_grant(user, "paperless.start", true).unwrap().unwrap();
    assert_eq!(
        s.set_grant(user, "paperless.start", true).unwrap(),
        Some(first)
    );
    let other = s.set_grant(user, "other.stop", true).unwrap().unwrap();
    drop(s);
    let mut s = Store::open(dir.path()).unwrap();
    s.reconcile_actions(&config("paperless.service", "Paperless"))
        .unwrap();
    assert_eq!(s.list_grants(user, None).unwrap().unwrap().items.len(), 2);
    assert_eq!(
        s.set_grant(user, "paperless.start", true).unwrap(),
        Some(first)
    );
    s.reconcile_actions(&config("changed.service", "Paperless"))
        .unwrap();
    let grants = s.list_grants(user, None).unwrap().unwrap();
    assert_eq!(grants.items.len(), 1);
    assert_eq!(grants.items[0].revision, other);
    let second = s.set_grant(user, "paperless.start", true).unwrap().unwrap();
    assert_ne!(second, first);
    s.reconcile_actions(&config("changed.service", "New description"))
        .unwrap();
    assert_eq!(s.list_grants(user, None).unwrap().unwrap().items.len(), 1);
    s.reconcile_actions(&Config::empty()).unwrap();
    assert!(s.list_grants(user, None).unwrap().unwrap().items.is_empty());
    s.reconcile_actions(&config("paperless.service", "Paperless"))
        .unwrap();
    assert!(s.list_grants(user, None).unwrap().unwrap().items.is_empty());
    assert_ne!(
        s.set_grant(user, "paperless.start", true).unwrap(),
        Some(first)
    );
    s.set_grant(user, "paperless.start", false).unwrap();
    s.set_grant(user, "paperless.start", false).unwrap();
    assert!(s.set_grant(user, "missing", true).unwrap().is_none());
    assert_eq!(s.set_grant(user, "/bin/sh", true), Err(Error::InvalidInput));
    s.set_grant(user, "paperless.start", true).unwrap();
    s.reset_installation("https://pi.lan").unwrap();
    s.reconcile_actions(&config("paperless.service", "Paperless"))
        .unwrap();
    let new = s.create_user("alice", "Alice").unwrap().id;
    assert!(s.list_grants(new, None).unwrap().unwrap().items.is_empty());
    assert!(
        s.set_grant(user, "paperless.start", true)
            .unwrap()
            .is_none()
    );
}
#[test]
fn explicit_v3_upgrade_and_corrupt_catalog() {
    let (d, mut s) = setup();
    s.configure_installation("https://pi.lan").unwrap();
    let user = s.create_user("alice", "Alice").unwrap();
    drop(s);
    let path = d.path().join("identity.sqlite3");
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("DROP TABLE grants; DROP TABLE actions; PRAGMA user_version=3;")
        .unwrap();
    drop(c);
    assert!(matches!(Store::open(d.path()), Err(Error::UpgradeRequired)));
    let old = Store::open_for_upgrade(d.path()).unwrap();
    assert!(old.list_actions(None).is_err());
    drop(old);
    let mut s = Store::upgrade(d.path()).unwrap();
    assert!(s.user_by_name("alice").unwrap().unwrap().id == user.id);
    assert_eq!(
        s.installation_origin().unwrap().unwrap().as_str(),
        "https://pi.lan"
    );
    s.reconcile_actions(&config("paperless.service", "Paperless"))
        .unwrap();
    drop(s);
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute("UPDATE actions SET definition=?1", [b"{}".as_slice()])
        .unwrap();
    drop(c);
    assert!(matches!(Store::open(d.path()), Err(Error::InvalidStore)));
}
#[test]
fn pagination_full_capacity_and_atomic_reconciliation_failure() {
    let (d, mut s) = setup();
    let mut text = String::from("schema_version=1\n[resources]\n");
    for i in 0..128 {
        text += &format!(
            "[actions.a{i:03}]\ndescription='Action'\nconfirmation=false\ntimeout_seconds=1\noutput_limit_bytes=0\noperation={{kind='systemd-start',unit='a.service'}}\n"
        );
    }
    let config = Config::parse(text.as_bytes()).unwrap();
    s.reconcile_actions(&config).unwrap();
    let u = s.create_user("alice", "Alice").unwrap().id;
    let mut after = None;
    let mut count = 0;
    loop {
        let p = s.list_actions(after.as_deref()).unwrap();
        for a in &p.items {
            s.set_grant(u, &a.id, true).unwrap();
        }
        count += p.items.len();
        after = p.next_after;
        if after.is_none() {
            break;
        }
    }
    assert_eq!(count, 128);
    let mut after = None;
    let mut count = 0;
    loop {
        let p = s.list_grants(u, after.as_deref()).unwrap().unwrap();
        count += p.items.len();
        after = p.next_after;
        if after.is_none() {
            break;
        }
    }
    assert_eq!(count, 128);
    let c = rusqlite::Connection::open(d.path().join("identity.sqlite3")).unwrap();
    c.execute_batch("CREATE TRIGGER fail_insert BEFORE INSERT ON actions BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
    assert!(s.reconcile_actions(&super_config()).is_err());
    assert!(s.list_actions(None).is_err());
    c.execute_batch("DROP TRIGGER fail_insert;").unwrap();
    drop(c);
    drop(s);
    let s = Store::open(d.path()).unwrap();
    assert_eq!(s.list_actions(None).unwrap().items.len(), 16);
    assert_eq!(s.list_grants(u, None).unwrap().unwrap().items.len(), 16);
}
fn super_config() -> Config {
    config("changed.service", "Changed")
}

#[test]
fn persisted_grants_cannot_reference_missing_users_or_stale_revisions() {
    for sql in [
        "UPDATE grants SET revision=zeroblob(32)",
        "UPDATE grants SET user_id=X'00000000000040008000000000000000'",
        "UPDATE grants SET action_id='missing'",
        "PRAGMA ignore_check_constraints=ON; UPDATE actions SET revision=X'01' WHERE id='paperless.start'",
    ] {
        let (d, mut s) = setup();
        let user = s.create_user("alice", "Alice").unwrap().id;
        s.reconcile_actions(&config("paperless.service", "Paperless"))
            .unwrap();
        s.set_grant(user, "paperless.start", true).unwrap();
        drop(s);
        let c = rusqlite::Connection::open(d.path().join("identity.sqlite3")).unwrap();
        c.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        c.execute_batch(sql).unwrap();
        drop(c);
        assert!(Store::open(d.path()).is_err());
    }
}
