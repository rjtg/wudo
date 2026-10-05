#![cfg(feature = "v2")]
use wudo_protocol::v2::*;
fn uid(n: u8) -> UserId {
    let mut id = [0; 16];
    id[6] = 0x40;
    id[8] = 0x80;
    id[15] = n;
    UserId(id)
}
fn encoded(q: &Request<'_>, r: &Response<'_>) -> Result<Vec<u8>> {
    let mut b = vec![0; MAX_PAYLOAD];
    let n = encode_response(&mut b, r, q, Endpoint::Admin)?;
    b.truncate(n);
    Ok(b)
}
#[test]
fn administrative_requests_are_strict_bounded_and_admin_only() {
    for q in [
        Request::UserList(UserList { after: None }),
        Request::UserList(UserList {
            after: Some(Name("alice")),
        }),
        Request::CredentialList(CredentialQuery {
            user_id: uid(1),
            after: Some(Blob(b"cursor")),
        }),
        Request::CredentialInspect(CredentialRef {
            user_id: uid(1),
            credential_id: Blob(b"id"),
        }),
        Request::CredentialRevoke(CredentialRef {
            user_id: uid(1),
            credential_id: Blob(b"id"),
        }),
    ] {
        let mut b = [0; 4096];
        let n = encode_request(&mut b, &q, Endpoint::Admin).unwrap();
        assert!(decode_request(&b[..n], Endpoint::Admin).unwrap() == q);
        assert!(matches!(
            decode_request(&b[..n], Endpoint::Web),
            Err(Error::NotPermitted)
        ));
    }
    for id in [&b""[..], &[1; 1024][..]] {
        for q in [
            Request::CredentialList(CredentialQuery {
                user_id: uid(1),
                after: Some(Blob(id)),
            }),
            Request::CredentialInspect(CredentialRef {
                user_id: uid(1),
                credential_id: Blob(id),
            }),
            Request::CredentialRevoke(CredentialRef {
                user_id: uid(1),
                credential_id: Blob(id),
            }),
        ] {
            assert!(encode_request(&mut [0; 4096], &q, Endpoint::Admin).is_err());
        }
    }
    for field in ["after", "CANARY"] {
        let mut b = [0; 4096];
        let mut e = minicbor::Encoder::new(minicbor::encode::write::Cursor::new(&mut b[..]));
        e.map(3)
            .unwrap()
            .str("version")
            .unwrap()
            .u8(2)
            .unwrap()
            .str("operation")
            .unwrap()
            .str("user.list")
            .unwrap()
            .str("body")
            .unwrap()
            .map(2)
            .unwrap()
            .str("after")
            .unwrap()
            .str("alice")
            .unwrap()
            .str(field)
            .unwrap()
            .str("bob")
            .unwrap();
        let n = e.into_writer().position();
        assert!(decode_request(&b[..n], Endpoint::Admin).is_err());
    }
}
#[test]
fn maximum_pages_fit_and_validate_cursor_order_and_identity() {
    let names: Vec<_> = (0..16)
        .map(|i| format!("u{i:02}{}", "x".repeat(61)))
        .collect();
    let label = "x".repeat(128);
    let users: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(i, n)| UserInfo {
            user_id: uid(i as u8),
            name: Name(n),
            label: Label(&label),
        })
        .collect();
    let q = Request::UserList(UserList { after: None });
    let mut p = UserPage {
        users: Items(users),
        next_after: Some(Name(&names[15])),
    };
    let b = encoded(&q, &Response::UserPage(p.clone())).unwrap();
    assert!(b.len() > 3000 && b.len() < 8192);
    assert!(decode_response(&b, &q, Endpoint::Admin).unwrap() == Response::UserPage(p.clone()));
    p.users.0[1].user_id = p.users.0[0].user_id;
    assert!(encoded(&q, &Response::UserPage(p.clone())).is_err());
    p.users.0[1].user_id = uid(1);
    p.users.0.swap(0, 1);
    assert!(encoded(&q, &Response::UserPage(p)).is_err());
    let ids: Vec<_> = (0..16).map(|i| vec![i + 1; 1023]).collect();
    let q = Request::CredentialList(CredentialQuery {
        user_id: uid(1),
        after: None,
    });
    let mut p = CredentialPage {
        user_id: uid(1),
        credentials: Items(
            ids.iter()
                .map(|id| CredentialEntry {
                    credential_id: Blob(id),
                    state: CredentialState::Revoked,
                })
                .collect(),
        ),
        next_after: Some(Blob(&ids[15])),
    };
    let b = encoded(&q, &Response::CredentialPage(p.clone())).unwrap();
    assert!(b.len() > 16384 && b.len() < 32768);
    assert!(
        decode_response(&b, &q, Endpoint::Admin).unwrap() == Response::CredentialPage(p.clone())
    );
    p.user_id = uid(2);
    assert!(encoded(&q, &Response::CredentialPage(p.clone())).is_err());
    p.user_id = uid(1);
    p.next_after = Some(Blob(&ids[0]));
    assert!(encoded(&q, &Response::CredentialPage(p.clone())).is_err());
    p.next_after = None;
    let cursor = Request::CredentialList(CredentialQuery {
        user_id: uid(1),
        after: Some(Blob(&ids[0])),
    });
    assert!(encoded(&cursor, &Response::CredentialPage(p.clone())).is_err());
    p.credentials.0[1] = p.credentials.0[0].clone();
    assert!(encoded(&q, &Response::CredentialPage(p)).is_err());
}
#[test]
fn single_record_replies_bind_owner_id_and_terminal_state() {
    let q = Request::CredentialRevoke(CredentialRef {
        user_id: uid(1),
        credential_id: Blob(b"id"),
    });
    let r = Response::CredentialRevoked(CredentialRevoked {
        user_id: uid(1),
        credential_id: Blob(b"id"),
        state: Revoked::Revoked,
    });
    let bytes = encoded(&q, &r).unwrap();
    assert!(decode_response(&bytes, &q, Endpoint::Admin).unwrap() == r);
    for (user_id, id) in [(uid(2), &b"id"[..]), (uid(1), &b"other"[..])] {
        let q = Request::CredentialRevoke(CredentialRef {
            user_id,
            credential_id: Blob(id),
        });
        assert!(decode_response(&bytes, &q, Endpoint::Admin).is_err());
    }
    // Preserve encoded length while corrupting the state enum.
    let mut invalid = bytes.clone();
    let start = invalid.windows(7).position(|w| w == b"revoked").unwrap();
    invalid[start..start + 7].copy_from_slice(b"unknown");
    assert!(decode_response(&invalid, &q, Endpoint::Admin).is_err());
    let inspect = Request::CredentialInspect(CredentialRef {
        user_id: uid(1),
        credential_id: Blob(b"id"),
    });
    let r = Response::CredentialInfo(CredentialInfo {
        user_id: uid(1),
        credential_id: Blob(b"other"),
        state: CredentialState::Active,
        fingerprint: Fingerprint([0; 32]),
    });
    assert!(encoded(&inspect, &r).is_err());
}
