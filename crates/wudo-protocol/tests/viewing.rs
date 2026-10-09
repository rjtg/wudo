#![cfg(feature = "v2")]
use wudo_protocol::v2::*;

fn query() -> Request<'static> {
    Request::ViewActions(ViewActions {
        token: ViewToken([7; 32]),
        after: None,
    })
}
fn action(id: &str) -> ViewAction<'_> {
    ViewAction {
        action_id: Name(id),
        description: Text("Start service"),
        revision: Blob(&[1; 32]),
        confirmation: true,
        state: UnitState::Inactive,
        availability: Availability::Available,
    }
}
#[test]
fn viewing_messages_are_web_only_and_responses_are_contextual() {
    let requests = [
        Request::ViewBegin(ViewBegin {
            user_name: Name("alice"),
        }),
        query(),
        Request::ViewFinish(ActionFinish {
            ceremony_id: CeremonyId([1; 32]),
            credential_id: Blob(b"id"),
            client_data: Blob(
                br#"{"type":"webauthn.get","challenge":"test","origin":"https://wudo.test"}"#,
            ),
            authenticator_data: Blob(&[0; 37]),
            signature: Blob(b"signature"),
            user_handle: None,
        }),
    ];
    let mut out = [0; 16384];
    for q in &requests {
        let n = encode_request(&mut out, q, Endpoint::Web).unwrap();
        assert!(decode_request(&out[..n], Endpoint::Web).is_ok());
        assert!(matches!(
            decode_request(&out[..n], Endpoint::Admin),
            Err(Error::NotPermitted)
        ));
    }
    let session = Response::ViewSession(ViewSession {
        token: ViewToken([2; 32]),
        remaining_ms: Number(300000),
    });
    assert!(encode_response(&mut out, &session, &requests[2], Endpoint::Web).is_ok());
    assert!(encode_response(&mut out, &session, &requests[0], Endpoint::Web).is_err());
    assert!(encode_response(&mut out, &session, &query(), Endpoint::Web).is_err());
}
#[test]
fn pages_reject_ambiguous_availability_order_cursors_and_lifetimes() {
    let q = query();
    let mut out = [0; 16384];
    let good = ViewPage {
        remaining_ms: Number(300000),
        actions: Items(vec![action("demo.start")]),
        next_after: None,
    };
    assert!(
        encode_response(
            &mut out,
            &Response::ViewPage(good.clone()),
            &q,
            Endpoint::Web
        )
        .is_ok()
    );
    let mut unknown = good.clone();
    unknown.actions.0[0].state = UnitState::Unknown;
    let mut duplicate = good.clone();
    duplicate.actions.0.push(action("demo.start"));
    let mut unsorted = good.clone();
    unsorted.actions.0.push(action("aaa.start"));
    let mut cursor = good.clone();
    cursor.next_after = Some(Name("demo.start"));
    let mut expired = good.clone();
    expired.remaining_ms = Number(0);
    let mut long = good.clone();
    long.remaining_ms = Number(600001);
    let mut controls = good.clone();
    controls.actions.0[0].description = Text("bad\ntext");
    for bad in [
        unknown, duplicate, unsorted, cursor, expired, long, controls,
    ] {
        assert!(encode_response(&mut out, &Response::ViewPage(bad), &q, Endpoint::Web).is_err());
    }
    let after = Request::ViewActions(ViewActions {
        token: ViewToken([7; 32]),
        after: Some(Name("demo.start")),
    });
    assert!(encode_response(&mut out, &Response::ViewPage(good), &after, Endpoint::Web).is_err());
}
#[test]
fn unknown_fields_and_invalid_token_lengths_are_rejected() {
    for size in [0, 31, 33] {
        let mut bytes = [0; 4096];
        let mut e = minicbor::Encoder::new(minicbor::encode::write::Cursor::new(&mut bytes[..]));
        e.map(3)
            .unwrap()
            .str("version")
            .unwrap()
            .u8(2)
            .unwrap()
            .str("operation")
            .unwrap()
            .str("view.actions")
            .unwrap()
            .str("body")
            .unwrap()
            .map(1)
            .unwrap()
            .str("token")
            .unwrap()
            .bytes(&vec![0; size])
            .unwrap();
        let n = e.into_writer().position();
        assert!(decode_request(&bytes[..n], Endpoint::Web).is_err());
    }
    let mut bytes = [0; 4096];
    let mut e = minicbor::Encoder::new(minicbor::encode::write::Cursor::new(&mut bytes[..]));
    e.map(3)
        .unwrap()
        .str("version")
        .unwrap()
        .u8(2)
        .unwrap()
        .str("operation")
        .unwrap()
        .str("view.actions")
        .unwrap()
        .str("body")
        .unwrap()
        .map(2)
        .unwrap()
        .str("token")
        .unwrap()
        .bytes(&[0; 32])
        .unwrap()
        .str("unit")
        .unwrap()
        .str("demo.service")
        .unwrap();
    let n = e.into_writer().position();
    assert!(decode_request(&bytes[..n], Endpoint::Web).is_err());
}

#[test]
fn full_page_fits_wire_budget_and_round_trips() {
    let names: Vec<_> = (0..16).map(|i| format!("action{i:02}")).collect();
    let description = "d".repeat(256);
    let actions = names
        .iter()
        .map(|name| ViewAction {
            description: Text(&description),
            ..action(name)
        })
        .collect();
    let page = Response::ViewPage(ViewPage {
        remaining_ms: Number(600000),
        actions: Items(actions),
        next_after: Some(Name(&names[15])),
    });
    let q = query();
    let mut out = vec![0; Operation::ViewActions.response_limit()];
    let n = encode_response(&mut out, &page, &q, Endpoint::Web).unwrap();
    assert!(decode_response(&out[..n], &q, Endpoint::Web).is_ok());
}
