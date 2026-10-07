use wudo_protocol::v2::*;
fn user() -> UserId {
    let mut id = [0; 16];
    id[6] = 0x40;
    id[8] = 0x80;
    UserId(id)
}
#[test]
fn grant_operations_are_admin_only_strict_and_context_bound() {
    let reference = GrantRef {
        user_id: user(),
        action_id: Name("paperless.start"),
    };
    let queries = [
        Request::ActionList(ActionList { after: None }),
        Request::GrantList(GrantQuery {
            user_id: user(),
            after: None,
        }),
        Request::GrantCreate(reference.clone()),
        Request::GrantRevoke(reference),
    ];
    for q in &queries {
        let mut bytes = [0; 4096];
        let n = encode_request(&mut bytes, q, Endpoint::Admin).unwrap();
        assert!(decode_request(&bytes[..n], Endpoint::Admin).is_ok());
        assert!(matches!(
            decode_request(&bytes[..n], Endpoint::Web),
            Err(Error::NotPermitted)
        ));
        assert!(encode_request(&mut bytes, q, Endpoint::Web).is_err());
    }
    let q = &queries[2];
    let revision = [1; 32];
    let mut bytes = [0; 4096];
    let good = GrantChanged {
        user_id: user(),
        action_id: Name("paperless.start"),
        revision: Blob(&revision),
        granted: true,
    };
    assert!(
        encode_response(
            &mut bytes,
            &Response::GrantChanged(good.clone()),
            q,
            Endpoint::Admin
        )
        .is_ok()
    );
    for bad in [
        GrantChanged {
            action_id: Name("other"),
            ..good.clone()
        },
        GrantChanged {
            granted: false,
            ..good.clone()
        },
        GrantChanged {
            revision: Blob(&[1; 31]),
            ..good.clone()
        },
    ] {
        assert!(
            encode_response(&mut bytes, &Response::GrantChanged(bad), q, Endpoint::Admin).is_err()
        );
    }
    let mut wrong = good;
    wrong.user_id.0[0] = 1;
    assert!(
        encode_response(
            &mut bytes,
            &Response::GrantChanged(wrong),
            q,
            Endpoint::Admin
        )
        .is_err()
    );
    for action in ["/bin/sh", "bad;arg", "A", "x\ny"] {
        assert!(
            encode_request(
                &mut bytes,
                &Request::GrantCreate(GrantRef {
                    user_id: user(),
                    action_id: Name(action)
                }),
                Endpoint::Admin
            )
            .is_err()
        );
    }
    for body in [r#"extra"#, r#"argv"#] {
        let mut encoded = [0; 4096];
        let mut e = minicbor::Encoder::new(&mut encoded[..]);
        e.map(3)
            .unwrap()
            .str("version")
            .unwrap()
            .u8(2)
            .unwrap()
            .str("operation")
            .unwrap()
            .str("action.list")
            .unwrap()
            .str("body")
            .unwrap()
            .map(1)
            .unwrap()
            .str(body)
            .unwrap()
            .str("x")
            .unwrap();
        let n = 4096 - e.writer().len();
        assert!(decode_request(&encoded[..n], Endpoint::Admin).is_err());
    }
}
#[test]
fn bounded_sorted_pages_reject_wrong_cursor_owner_and_display() {
    let names: Vec<_> = (0..17).map(|n| format!("a{n:02}")).collect();
    let revision = [2; 32];
    let description = "x".repeat(256);
    let entries: Vec<_> = names
        .iter()
        .map(|n| ActionEntry {
            action_id: Name(n),
            description: Text(&description),
            revision: Blob(&revision),
        })
        .collect();
    let q = Request::ActionList(ActionList { after: None });
    let mut bytes = [0; 8192];
    let p = ActionPage {
        actions: Items(entries[..16].to_vec()),
        next_after: Some(Name(&names[15])),
    };
    assert!(
        encode_response(
            &mut bytes,
            &Response::ActionPage(p.clone()),
            &q,
            Endpoint::Admin
        )
        .is_ok()
    );
    for bad in [
        ActionPage {
            actions: Items(entries.clone()),
            next_after: None,
        },
        ActionPage {
            next_after: Some(Name("wrong")),
            ..p.clone()
        },
        ActionPage {
            actions: Items(entries[..16].iter().rev().cloned().collect()),
            ..p.clone()
        },
    ] {
        assert!(
            encode_response(&mut bytes, &Response::ActionPage(bad), &q, Endpoint::Admin).is_err()
        );
    }
    let mut p = p;
    p.actions.0[0].description = Text("bad\ntext");
    assert!(encode_response(&mut bytes, &Response::ActionPage(p), &q, Endpoint::Admin).is_err());
    let q = Request::GrantList(GrantQuery {
        user_id: user(),
        after: None,
    });
    let mut other = user();
    other.0[0] = 2;
    assert!(
        encode_response(
            &mut bytes,
            &Response::GrantPage(GrantPage {
                user_id: other,
                actions: Items(vec![]),
                next_after: None
            }),
            &q,
            Endpoint::Admin
        )
        .is_err()
    );
}
