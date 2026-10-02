#![cfg(feature = "v2")]
use minicbor::{Encoder, encode::write::Cursor};
use wudo_protocol::v2::*;

const UID: UserId = UserId([1, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16]);
const CREATE: &[u8] =
    br#"{"type":"webauthn.create","challenge":"test","origin":"https://wudo.example.test"}"#;
const GET: &[u8] =
    br#"{"type":"webauthn.get","challenge":"test","origin":"https://wudo.example.test"}"#;

fn registration() -> Request<'static> {
    Request::RegistrationFinish(RegistrationFinish {
        ceremony_id: CeremonyId([1; 32]),
        credential_id: Blob(b"credential"),
        client_data: Blob(CREATE),
        attestation_object: Blob(b"\xa0"),
        client_extensions: RegistrationExtensions {
            resident_key: None,
            cred_protect: None,
        },
    })
}
fn assertion() -> Request<'static> {
    Request::ActionFinish(ActionFinish {
        ceremony_id: CeremonyId([1; 32]),
        credential_id: Blob(b"credential"),
        client_data: Blob(GET),
        authenticator_data: Blob(&[0; 37]),
        signature: Blob(b"signature"),
        user_handle: Some(UID),
    })
}
fn requests() -> Vec<(Request<'static>, Endpoint)> {
    vec![
        (Request::Status, Endpoint::Admin),
        (
            Request::UserCreate(UserCreate {
                name: Name("alice"),
                label: Label("Alice"),
            }),
            Endpoint::Admin,
        ),
        (
            Request::EnrollmentOpen(EnrollmentOpen {
                user_id: UID,
                mode: Mode::Confirm,
            }),
            Endpoint::Admin,
        ),
        (
            Request::EnrollmentInspect(EnrollmentRef {
                enrollment_id: EnrollmentId([2; 32]),
            }),
            Endpoint::Admin,
        ),
        (
            Request::EnrollmentCancel(EnrollmentRef {
                enrollment_id: EnrollmentId([2; 32]),
            }),
            Endpoint::Admin,
        ),
        (
            Request::EnrollmentApprove(EnrollmentApprove {
                enrollment_id: EnrollmentId([2; 32]),
                candidate_id: CandidateId([3; 32]),
            }),
            Endpoint::Admin,
        ),
        (
            Request::RegistrationBegin(RegistrationBegin {
                ticket: Ticket([4; 32]),
            }),
            Endpoint::Web,
        ),
        (Request::RegistrationBeginInsecure, Endpoint::Web),
        (registration(), Endpoint::Web),
        (
            Request::ActionBegin(ActionBegin {
                user_name: Name("alice"),
                action_id: Name("paperless.start"),
            }),
            Endpoint::Web,
        ),
        (assertion(), Endpoint::Web),
    ]
}
fn encoded(request: &Request<'_>, endpoint: Endpoint) -> Vec<u8> {
    let mut out = vec![0; MAX_PAYLOAD];
    let n = encode_request(&mut out, request, endpoint).unwrap();
    out.truncate(n);
    out
}
fn raw(operation: &str, body: impl FnOnce(&mut Encoder<Cursor<&mut [u8]>>)) -> Vec<u8> {
    let mut out = vec![0; MAX_PAYLOAD];
    let mut e = Encoder::new(Cursor::new(out.as_mut_slice()));
    e.map(3)
        .unwrap()
        .str("version")
        .unwrap()
        .u8(2)
        .unwrap()
        .str("operation")
        .unwrap()
        .str(operation)
        .unwrap()
        .str("body")
        .unwrap();
    body(&mut e);
    let n = e.into_writer().position();
    out.truncate(n);
    out
}

#[test]
fn every_request_round_trips_and_obeys_endpoint_policy() {
    for (request, endpoint) in requests() {
        let bytes = encoded(&request, endpoint);
        assert!(decode_request(&bytes, endpoint).unwrap() == request);
        let other = if endpoint == Endpoint::Admin {
            Endpoint::Web
        } else {
            Endpoint::Admin
        };
        if request.operation() != Operation::Status {
            assert!(matches!(
                decode_request(&bytes, other),
                Err(Error::NotPermitted)
            ));
        } else {
            assert!(decode_request(&bytes, other).is_ok());
        }
        for prefix in 0..bytes.len() {
            assert!(decode_request(&bytes[..prefix], endpoint).is_err());
        }
        let mut extra = bytes;
        extra.push(0);
        assert!(matches!(
            decode_request(&extra, endpoint),
            Err(Error::InvalidRequest)
        ));
    }
}

fn creation() -> CreationOptions<'static> {
    CreationOptions {
        rp: Rp {
            id: Text("wudo.example.test"),
            name: Text("Wudo"),
        },
        user: User {
            id: UID,
            name: Name("alice"),
            display_name: Label("Alice"),
        },
        challenge: Challenge([5; 32]),
        timeout_ms: Number(120000),
        algorithms: Algorithms(vec![-7, -257]),
        exclude_credentials: CredentialList(vec![Blob(b"old-key")]),
        user_verification: Required::Required,
        resident_key: Discouraged::Discouraged,
        attestation: NoAttestation::None,
        extensions: CreationExtensions {
            cred_protect: Number(3),
            enforce_protect: false,
            uvm: true,
            cred_props: true,
        },
    }
}
fn replies() -> Vec<Response<'static>> {
    vec![
        Response::Status(StatusResult {
            status: Ready::Ready,
        }),
        Response::UserCreated(UserCreated { user_id: UID }),
        Response::Opened(Opened {
            enrollment_id: EnrollmentId([2; 32]),
            remaining_ms: Number(600000),
            ticket: Some(Ticket([4; 32])),
        }),
        Response::OpenInspection(OpenInspection {
            state: OpenState::Open,
            user_id: UID,
            mode: Mode::Confirm,
            remaining_ms: Number(10),
        }),
        Response::Cancelled(CancelledResult {
            state: Cancelled::Cancelled,
        }),
        Response::Activated(Activated {
            state: Active::Active,
            credential_id: Blob(b"credential"),
        }),
        Response::RegistrationChallenge(RegistrationChallenge {
            ceremony_id: CeremonyId([5; 32]),
            remaining_ms: Number(120000),
            options: creation(),
        }),
        Response::RegistrationChallenge(RegistrationChallenge {
            ceremony_id: CeremonyId([5; 32]),
            remaining_ms: Number(120000),
            options: creation(),
        }),
        Response::Registered(Registered {
            state: RegistrationState::PendingApproval,
        }),
        Response::ActionChallenge(ActionChallenge {
            ceremony_id: CeremonyId([5; 32]),
            remaining_ms: Number(120000),
            options: RequestOptions {
                rp_id: Text("wudo.example.test"),
                challenge: Challenge([6; 32]),
                timeout_ms: Number(120000),
                allow_credentials: CredentialList(vec![Blob(b"credential")]),
                user_verification: Required::Required,
            },
        }),
        Response::Admitted(Admitted {
            state: Accepted::Accepted,
            operation_id: OperationId([7; 32]),
        }),
    ]
}
fn response_roundtrip(response: &Response<'_>, request: &Request<'_>, endpoint: Endpoint) {
    let mut out = vec![0; MAX_PAYLOAD];
    let n = encode_response(&mut out, response, request, endpoint).unwrap();
    assert!(decode_response(&out[..n], request, endpoint).unwrap() == *response);
    for prefix in 0..n {
        assert!(decode_response(&out[..prefix], request, endpoint).is_err());
    }
}

#[test]
fn all_success_and_error_responses_are_context_checked() {
    for ((request, endpoint), reply) in requests().into_iter().zip(replies()) {
        response_roundtrip(&reply, &request, endpoint);
        for error in [
            Error::InvalidRequest,
            Error::UnsupportedOperation,
            Error::NotPermitted,
            Error::Unavailable,
            Error::VerificationFailed,
            Error::Busy,
            Error::InternalError,
        ] {
            response_roundtrip(&Response::Error(error), &request, endpoint);
        }
    }
    let inspect = Request::EnrollmentInspect(EnrollmentRef {
        enrollment_id: EnrollmentId([2; 32]),
    });
    let mut candidate = CandidateInspection {
        state: PendingApproval::PendingApproval,
        user_id: UID,
        mode: Mode::Confirm,
        remaining_ms: Number(5),
        candidate_id: CandidateId([3; 32]),
        credential_id: Blob(b"key"),
        fingerprint: Fingerprint([4; 32]),
    };
    response_roundtrip(
        &Response::CandidateInspection(candidate.clone()),
        &inspect,
        Endpoint::Admin,
    );
    candidate.mode = Mode::Insecure;
    assert!(
        encode_response(
            &mut [0; 4096],
            &Response::CandidateInspection(candidate),
            &inspect,
            Endpoint::Admin
        )
        .is_err()
    );
    let request = Request::EnrollmentOpen(EnrollmentOpen {
        user_id: UID,
        mode: Mode::Insecure,
    });
    let mut opened = Opened {
        enrollment_id: EnrollmentId([1; 32]),
        remaining_ms: Number(1),
        ticket: None,
    };
    response_roundtrip(&Response::Opened(opened.clone()), &request, Endpoint::Admin);
    opened.ticket = Some(Ticket([2; 32]));
    assert!(
        encode_response(
            &mut [0; 4096],
            &Response::Opened(opened),
            &request,
            Endpoint::Admin
        )
        .is_err()
    );
    assert!(
        encode_response(
            &mut [0; 4096],
            &Response::Error(Error::Conflict),
            &Request::Status,
            Endpoint::Web
        )
        .is_err()
    );
    response_roundtrip(
        &Response::Error(Error::Conflict),
        &Request::Status,
        Endpoint::Admin,
    );
    assert!(
        encode_response(
            &mut [0; 4096],
            &replies()[1],
            &Request::Status,
            Endpoint::Admin
        )
        .is_err()
    );
}

#[test]
fn v1_is_unchanged_and_versions_never_downgrade() {
    let v1 = wudo_protocol::encode_request().unwrap();
    assert!(wudo_protocol::decode_request(v1.as_ref()).is_ok());
    assert!(matches!(
        decode_request(v1.as_ref(), Endpoint::Admin),
        Err(Error::UnsupportedVersion)
    ));
    let v2 = encoded(&Request::Status, Endpoint::Admin);
    assert!(wudo_protocol::decode_request(&v2).is_err());
    assert!(wudo_protocol::payload_len(4097u32.to_be_bytes()).is_err());
    for n in [0, 65537, u32::MAX] {
        assert!(payload_len(n.to_be_bytes()).is_err());
    }
    for n in [1u32, 4096, 65536] {
        assert_eq!(payload_len(n.to_be_bytes()), Ok(n as usize));
    }
    assert!(decode_request(&vec![0; 65537], Endpoint::Admin).is_err());
}

#[test]
fn rejects_injection_duplicates_and_wrong_shapes() {
    for field in [
        "argv",
        "path",
        "command",
        "mode",
        "user_id",
        "confirmed",
        "grants",
    ] {
        let bytes = raw("registration.begin_insecure", |e| {
            e.map(1).unwrap().str(field).unwrap().str("CANARY").unwrap();
        });
        assert!(matches!(
            decode_request(&bytes, Endpoint::Web),
            Err(Error::InvalidRequest)
        ));
    }
    let bytes = raw("user.create", |e| {
        e.map(3)
            .unwrap()
            .str("name")
            .unwrap()
            .str("alice")
            .unwrap()
            .str("label")
            .unwrap()
            .str("Alice")
            .unwrap()
            .str("name")
            .unwrap()
            .str("other")
            .unwrap();
    });
    assert!(decode_request(&bytes, Endpoint::Admin).is_err());
    let bytes = raw("action.begin", |e| {
        e.map(1)
            .unwrap()
            .str("user_name")
            .unwrap()
            .str("alice")
            .unwrap();
    });
    assert!(decode_request(&bytes, Endpoint::Web).is_err());
    for body in [
        vec![0xf6],
        vec![0x80],
        vec![0xbf, 0xff],
        vec![0xc0, 0xa0],
        vec![0xa1, 0x61, 0xff, 0x00],
    ] {
        let mut bytes = encoded(&Request::Status, Endpoint::Admin);
        bytes.pop();
        bytes.extend(body);
        assert!(decode_request(&bytes, Endpoint::Admin).is_err());
    }
    // Duplicate version encoded using a non-shortest text-string length.
    let mut bytes = encoded(&Request::Status, Endpoint::Admin);
    bytes[0] = 0xa4;
    bytes.extend_from_slice(b"\x78\x07version\x02");
    assert!(decode_request(&bytes, Endpoint::Admin).is_err());
    assert_eq!(format!("{:?}", Error::InvalidRequest), "InvalidRequest");
}

#[test]
fn unordered_and_non_shortest_encodings_are_accepted() {
    let bytes = b"\xa3\x64body\xb8\x00\x69operation\x66status\x67version\x18\x02";
    assert!(decode_request(bytes, Endpoint::Admin).unwrap() == Request::Status);
}

#[test]
fn invalid_outbound_values_are_rejected_too() {
    for name in ["", "Alice", "a..b", "a_", "/etc/shadow", "a;b", "a b"] {
        let request = Request::UserCreate(UserCreate {
            name: Name(name),
            label: Label("Alice"),
        });
        assert!(encode_request(&mut [0; 4096], &request, Endpoint::Admin).is_err());
    }
    let request = Request::UserCreate(UserCreate {
        name: Name("alice"),
        label: Label("CANARY\n"),
    });
    assert!(encode_request(&mut [0; 4096], &request, Endpoint::Admin).is_err());
    let request = Request::EnrollmentOpen(EnrollmentOpen {
        user_id: UserId([0; 16]),
        mode: Mode::Confirm,
    });
    assert!(encode_request(&mut [0; 4096], &request, Endpoint::Admin).is_err());
    assert!(encode_request(&mut [0; 2], &Request::Status, Endpoint::Admin).is_err());
    for case in 0..4 {
        let mut options = creation();
        match case {
            0 => options.algorithms = Algorithms(vec![-7, -7]),
            1 => options.exclude_credentials = CredentialList(vec![Blob(b"id"), Blob(b"id")]),
            2 => options.extensions.uvm = false,
            _ => options.timeout_ms = Number(120001),
        }
        let response = Response::RegistrationChallenge(RegistrationChallenge {
            ceremony_id: CeremonyId([1; 32]),
            remaining_ms: Number(120000),
            options,
        });
        assert!(
            encode_response(
                &mut [0; 4096],
                &response,
                &Request::RegistrationBeginInsecure,
                Endpoint::Web
            )
            .is_err()
        );
    }
}

#[test]
fn embedded_json_and_cbor_are_bounded_without_reserialization() {
    for json in [
        br#"{"type":"webauthn.create","challenge":"x","origin":"x","origin":"y"}"#.as_slice(),
        br#"{"type":"webauthn.create","challenge":"x","origin":"x","crossOrigin":true}"#,
        br#"{"type":"webauthn.create","challenge":"x","origin":"x","crossOrigin":null}"#,
        br#"{"type":"webauthn.create","challenge":"x","origin":"x","extra":{}}"#,
        br#"{"type":"webauthn.get","challenge":"x","origin":"x"}"#,
        b"{} {}",
        b"[]",
        b"{\"type\":\"\xff\"}",
    ] {
        let Request::RegistrationFinish(mut v) = registration() else {
            unreachable!()
        };
        v.client_data = Blob(json);
        assert!(
            encode_request(
                &mut [0; 40960],
                &Request::RegistrationFinish(v),
                Endpoint::Web
            )
            .is_err()
        );
    }
    for cbor in [
        &b"\xa2\x61x\x01\x61x\x02"[..],
        b"\xbf\xff",
        b"\xa1\x61x\xc0\x00",
        b"\xa0\x00",
        b"\x80",
    ] {
        let Request::RegistrationFinish(mut v) = registration() else {
            unreachable!()
        };
        v.attestation_object = Blob(cbor);
        assert!(
            encode_request(
                &mut [0; 40960],
                &Request::RegistrationFinish(v),
                Endpoint::Web
            )
            .is_err()
        );
    }
    let original = b" { \"origin\":\"https://wudo.example.test\", \"challenge\":\"test\", \"type\":\"webauthn.create\" } ";
    let Request::RegistrationFinish(mut v) = registration() else {
        unreachable!()
    };
    v.client_data = Blob(original);
    let bytes = encoded(&Request::RegistrationFinish(v), Endpoint::Web);
    let Request::RegistrationFinish(decoded) = decode_request(&bytes, Endpoint::Web).unwrap()
    else {
        unreachable!()
    };
    assert_eq!(decoded.client_data.0, original);
    assert!(decoded.client_data.0.as_ptr() >= bytes.as_ptr());
}

#[test]
fn depth_collection_and_total_item_budgets_are_enforced_before_dispatch() {
    let bytes = raw("future", |e| {
        e.map(1).unwrap().str("x").unwrap();
        for _ in 0..9 {
            e.array(1).unwrap();
        }
        e.u8(0).unwrap();
    });
    assert!(matches!(
        decode_request(&bytes, Endpoint::Web),
        Err(Error::InvalidRequest)
    ));
    let bytes = raw("future", |e| {
        e.map(1).unwrap().str("x").unwrap().array(16).unwrap();
        for _ in 0..16 {
            e.array(16).unwrap();
            for _ in 0..16 {
                e.array(2).unwrap().u8(0).unwrap().u8(0).unwrap();
            }
        }
    });
    assert!(matches!(
        decode_request(&bytes, Endpoint::Web),
        Err(Error::InvalidRequest)
    ));
    let bytes = raw("future", |e| {
        e.map(1).unwrap().str("x").unwrap().array(u64::MAX).unwrap();
    });
    assert!(matches!(
        decode_request(&bytes, Endpoint::Web),
        Err(Error::InvalidRequest)
    ));
    let bytes = raw("future", |e| {
        e.map(0).unwrap();
    });
    assert!(matches!(
        decode_request(&bytes, Endpoint::Web),
        Err(Error::UnsupportedOperation)
    ));
}

#[test]
fn maximum_field_requests_fit_caps_and_overlimit_fields_fail() {
    let mut json = CREATE.to_vec();
    json.resize(4096, b' ');
    let id = vec![1; 1023];
    let mut attestation = vec![0; 32768];
    let mut e = Encoder::new(Cursor::new(attestation.as_mut_slice()));
    e.map(1)
        .unwrap()
        .str("pad")
        .unwrap()
        .bytes(&vec![0; 32760])
        .unwrap();
    assert_eq!(e.into_writer().position(), 32768);
    let mut request = RegistrationFinish {
        ceremony_id: CeremonyId([1; 32]),
        credential_id: Blob(&id),
        client_data: Blob(&json),
        attestation_object: Blob(&attestation),
        client_extensions: RegistrationExtensions {
            resident_key: Some(false),
            cred_protect: Some(Number(3)),
        },
    };
    assert_eq!(
        encoded(&Request::RegistrationFinish(request.clone()), Endpoint::Web).len(),
        38080
    );
    let huge_id = vec![0; 1024];
    request.credential_id = Blob(&huge_id);
    assert!(
        encode_request(
            &mut vec![0; MAX_PAYLOAD],
            &Request::RegistrationFinish(request),
            Endpoint::Web
        )
        .is_err()
    );
    let mut json = GET.to_vec();
    json.resize(4096, b' ');
    let auth = vec![0; 4096];
    let sig = vec![0; 1024];
    let request = ActionFinish {
        ceremony_id: CeremonyId([1; 32]),
        credential_id: Blob(&id),
        client_data: Blob(&json),
        authenticator_data: Blob(&auth),
        signature: Blob(&sig),
        user_handle: Some(UID),
    };
    assert_eq!(
        encoded(&Request::ActionFinish(request), Endpoint::Web).len(),
        10421
    );
}

#[test]
fn administrative_store_operations_are_strict_and_admin_only() {
    for request in [
        Request::StoreInitialize,
        Request::StoreUpgrade,
        Request::UserInspect(UserInspect {
            name: Name("alice"),
        }),
    ] {
        let bytes = encoded(&request, Endpoint::Admin);
        assert!(decode_request(&bytes, Endpoint::Admin).unwrap() == request);
        assert!(matches!(
            decode_request(&bytes, Endpoint::Web),
            Err(Error::NotPermitted)
        ));
        for n in 0..bytes.len() {
            assert!(decode_request(&bytes[..n], Endpoint::Admin).is_err());
        }
        let response = if matches!(request, Request::UserInspect(_)) {
            Response::UserInfo(UserInfo {
                user_id: UID,
                name: Name("alice"),
                label: Label("Alice"),
            })
        } else {
            Response::StoreReady(StoreReady {
                state: Ready::Ready,
            })
        };
        response_roundtrip(&response, &request, Endpoint::Admin);
    }
}
