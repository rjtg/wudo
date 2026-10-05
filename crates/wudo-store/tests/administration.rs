use std::{fs, os::unix::fs::PermissionsExt};
use wudo_store::{Error, Store};

#[test]
fn users_paginate_without_credentials_and_require_ready_storage() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut s = Store::initialize(dir.path()).unwrap();
    assert!(s.list_users(None).unwrap().items.is_empty());
    for n in (0..64).rev() {
        s.create_user(&format!("user{n:02}"), "Label").unwrap();
    }
    let mut cursor = None;
    let mut names = Vec::new();
    loop {
        let page = s.list_users(cursor.as_deref()).unwrap();
        assert_eq!(page.items.len(), 16);
        cursor = page.next_after;
        names.extend(page.items.into_iter().map(|u| u.name));
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(
        names,
        (0..64).map(|n| format!("user{n:02}")).collect::<Vec<_>>()
    );
    assert!(s.list_users(Some("z")).unwrap().items.is_empty());
    assert!(matches!(
        s.list_users(Some("INVALID")),
        Err(Error::InvalidInput)
    ));
}
