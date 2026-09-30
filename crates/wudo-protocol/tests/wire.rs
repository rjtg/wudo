use wudo_protocol::{
    ErrorCode, Request, Response, decode_request, decode_response, encode_request, encode_response,
    payload_len,
};

const REQUEST: &[u8] = b"\xa2\x67version\x01\x69operation\x66status";

#[test]
fn golden_status_and_error_round_trips() {
    assert_eq!(encode_request().unwrap().as_ref(), REQUEST);
    assert_eq!(decode_request(REQUEST), Ok(Request::Status));
    let ready = b"\xa3\x67version\x01\x66result\x62ok\x66status\x65ready";
    assert_eq!(encode_response(Response::Ready).unwrap().as_ref(), ready);
    for response in [
        Response::Ready,
        Response::Error(ErrorCode::InvalidRequest),
        Response::Error(ErrorCode::UnsupportedVersion),
        Response::Error(ErrorCode::UnsupportedOperation),
    ] {
        assert_eq!(
            decode_response(encode_response(response).unwrap().as_ref()),
            Ok(response)
        );
    }
}
#[test]
fn rejects_bad_frames_and_every_truncated_prefix() {
    for n in [0u32, 4097, u32::MAX] {
        assert!(payload_len(n.to_be_bytes()).is_err());
    }
    for n in [1u32, 4096] {
        assert_eq!(payload_len(n.to_be_bytes()), Ok(n as usize));
    }
    for end in 0..REQUEST.len() {
        assert!(decode_request(&REQUEST[..end]).is_err());
    }
    let mut extra = REQUEST.to_vec();
    extra.push(0);
    assert_eq!(decode_request(&extra), Err(ErrorCode::InvalidRequest));
    assert!(decode_request(&vec![0; 4097]).is_err());
}
#[test]
fn rejects_unknown_duplicate_nested_and_wrong_types() {
    for input in [
        &b"\xa2\x67version\x01\x67version\x01"[..],
        &b"\xa2\x67version\x01\x67unknown\x66status"[..],
        &b"\xa2\x67version\xf5\x69operation\x66status"[..],
        &b"\xa2\x67version\x20\x69operation\x66status"[..],
        &b"\xa2\x67version\x01\x69operation\xa0"[..],
        &b"\xa2\x67version\x01\x69operation\x46status"[..],
        &b"\xbf\x67version\x01\x69operation\x66status\xff"[..],
        &b"\xc0\xa2\x67version\x01\x69operation\x66status"[..],
        &b"\xa2\x67version\x01\x69operation\x61\xff"[..],
        &b"\xa2\x67version\x01\x69operation\x7f\x66status\xff"[..],
        &b"\xa2\x67version\x01\x69operation\x7b\xff\xff\xff\xff\xff\xff\xff\xff"[..],
        &b"\xbb\xff\xff\xff\xff\xff\xff\xff\xff"[..],
        &b"{\"version\":1,\"operation\":\"status\"}"[..],
    ] {
        assert_eq!(decode_request(input), Err(ErrorCode::InvalidRequest));
    }
}
#[test]
fn order_and_non_shortest_encodings_do_not_change_meaning() {
    assert_eq!(
        decode_request(b"\xa2\x69operation\x66status\x67version\x01"),
        Ok(Request::Status)
    );
    assert_eq!(
        decode_request(b"\xb8\x02\x78\x07version\x18\x01\x69operation\x78\x06status"),
        Ok(Request::Status)
    );
    assert_eq!(
        decode_request(b"\xa2\x67version\x01\x78\x07version\x01"),
        Err(ErrorCode::InvalidRequest)
    );
}
#[test]
fn error_precedence_and_response_strictness() {
    assert_eq!(
        decode_request(b"\xa2\x67version\x02\x69operation\x64nope"),
        Err(ErrorCode::UnsupportedVersion)
    );
    assert_eq!(
        decode_request(b"\xa2\x67version\x01\x69operation\x64nope"),
        Err(ErrorCode::UnsupportedOperation)
    );
    assert_eq!(
        decode_request(b"\xa2\x67version\x02\x67unknown\x64nope"),
        Err(ErrorCode::InvalidRequest)
    );
    for input in [
        &b"\xa3\x67version\x01\x66result\x62ok\x64code\x65ready"[..],
        &b"\xa3\x67version\x02\x66result\x62ok\x66status\x65ready"[..],
        &b"\xa3\x67version\x01\x66result\x65error\x64code\x64nope"[..],
        &b"\xa3\x67version\x01\x66result\x62ok\x66result\x62ok"[..],
    ] {
        assert!(decode_response(input).is_err());
    }
}
