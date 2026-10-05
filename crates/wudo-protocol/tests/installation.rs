#![cfg(feature = "v2")]
use wudo_protocol::v2::*;
#[test]
fn origin_grammar_and_normalization() {
    for (value, canonical, rp) in [
        (
            "https://wudo.home.example/",
            "https://wudo.home.example",
            "wudo.home.example",
        ),
        (
            "https://wudo.home.example:443",
            "https://wudo.home.example",
            "wudo.home.example",
        ),
        ("https://pi.lan:8443", "https://pi.lan:8443", "pi.lan"),
    ] {
        let parsed = InstallationOrigin::parse(value).unwrap();
        assert_eq!(parsed.as_str(), canonical);
        assert_eq!(parsed.rp_id(), rp);
    }
    for value in [
        "",
        "http://pi.lan",
        "https://PI.lan",
        "https://pi.lan.",
        "https://pi.lan/path",
        "https://pi.lan/?q=x",
        "https://pi.lan/#x",
        "https://u@pi.lan",
        "https://127.0.0.1",
        "https://[::1]",
        "https://2130706433",
        "https://pi.lan:0",
        "https://pi.lan:65536",
        "https://pi.lan:0443",
        "https://pi..lan",
        "https://-pi.lan",
        "https://pi-.lan",
        "https://pi_lan",
        "https://pï.lan",
        "https://%70i.lan",
        "https://pi.lan\\x",
        " https://pi.lan",
        "https://pi.lan\n",
        "https://pi.lan//",
    ] {
        assert!(
            InstallationOrigin::parse(value).is_err(),
            "accepted {value}"
        );
    }
    assert!(InstallationOrigin::parse(&format!("https://{}.lan", "a".repeat(64))).is_err());
}
#[test]
fn settings_operation_is_strict_admin_only_and_legacy_is_unchanged() {
    let req = Request::InstallationInitialize(InstallationInitialize {
        origin: Text("https://pi.lan"),
    });
    let mut bytes = [0; 4096];
    let n = encode_request(&mut bytes, &req, Endpoint::Admin).unwrap();
    assert!(decode_request(&bytes[..n], Endpoint::Admin).unwrap() == req);
    assert!(matches!(
        decode_request(&bytes[..n], Endpoint::Web),
        Err(Error::NotPermitted)
    ));
    let mut empty = [0; 4096];
    let m = encode_request(&mut empty, &Request::StoreInitialize, Endpoint::Admin).unwrap();
    assert!(matches!(
        decode_request(&empty[..m], Endpoint::Admin),
        Ok(Request::StoreInitialize)
    ));
    let invalid = Request::InstallationInitialize(InstallationInitialize {
        origin: Text("http://pi.lan"),
    });
    assert!(encode_request(&mut bytes, &invalid, Endpoint::Admin).is_err());
    // Compose malformed bodies through the established CBOR library.
    for body in [0, 1, 2] {
        let mut b = [0; 4096];
        let mut e = minicbor::Encoder::new(&mut b[..]);
        e.map(3)
            .unwrap()
            .str("version")
            .unwrap()
            .u8(2)
            .unwrap()
            .str("operation")
            .unwrap()
            .str("installation.initialize")
            .unwrap()
            .str("body")
            .unwrap();
        if body == 0 {
            e.map(0).unwrap();
        } else {
            e.map(2)
                .unwrap()
                .str("origin")
                .unwrap()
                .str("https://pi.lan")
                .unwrap()
                .str(if body == 1 { "origin" } else { "rp_id" })
                .unwrap()
                .str("pi.lan")
                .unwrap();
        }
        let left = e.into_writer().len();
        let n = b.len() - left;
        assert!(decode_request(&b[..n], Endpoint::Admin).is_err());
    }
}

#[test]
fn reset_is_a_distinct_explicit_root_operation() {
    let request = Request::InstallationReset(InstallationInitialize {
        origin: Text("https://new.example"),
    });
    let mut bytes = [0; 4096];
    let n = encode_request(&mut bytes, &request, Endpoint::Admin).unwrap();
    assert!(decode_request(&bytes[..n], Endpoint::Admin).unwrap() == request);
    assert!(matches!(
        decode_request(&bytes[..n], Endpoint::Web),
        Err(Error::NotPermitted)
    ));
    let mut response = [0; 4096];
    let n = encode_response(
        &mut response,
        &Response::StoreReady(StoreReady {
            state: Ready::Ready,
        }),
        &request,
        Endpoint::Admin,
    )
    .unwrap();
    assert!(matches!(
        decode_response(&response[..n], &request, Endpoint::Admin),
        Ok(Response::StoreReady(_))
    ));
}
