//! Characterize the pinned upstream parser, not a Wudo parsing implementation.
//! Fixtures below are unsigned bytes. Acceptance here is NOT authentication.
use webauthn_rs_core::{
    internals::AuthenticatorData,
    proto::{Authentication, Registration},
};

fn assertion(extensions: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = vec![0; 32]; // Synthetic RP hash.
    bytes.push(if extensions.is_some() { 0x85 } else { 0x05 }); // UP/UV, optional ED.
    bytes.extend_from_slice(&[0; 4]); // Counter.
    if let Some(extension) = extensions {
        bytes.extend_from_slice(extension);
    }
    bytes
}

#[test]
fn upstream_ignores_trailing_authenticator_bytes() {
    let base = assertion(None);
    assert!(AuthenticatorData::<Authentication>::try_from(base.as_slice()).is_ok());
    for suffix in [&[0][..], &[0xa0], b"trailing"] {
        let mut bytes = base.clone();
        bytes.extend_from_slice(suffix);
        assert!(AuthenticatorData::<Authentication>::try_from(bytes.as_slice()).is_ok());
    }
    for n in 0..37 {
        assert!(AuthenticatorData::<Authentication>::try_from(&base[..n]).is_err());
    }
}

#[test]
fn upstream_extension_cbor_does_not_enforce_wudo_profile() {
    // Duplicate unknown text key, including equivalent non-shortest encoding.
    let duplicate = [0xa2, 0x61, b'x', 0x00, 0x78, 0x01, b'x', 0x01];
    let indefinite = [0xbf, 0x61, b'x', 0x00, 0xff];
    let mut deep = vec![0xa1, 0x61, b'x'];
    deep.extend_from_slice(&[0x81; 10]);
    deep.push(0);
    let mut many = vec![0xa1, 0x61, b'x', 0x99, 0x01, 0x01];
    many.extend_from_slice(&[0; 257]);
    for extension in [
        duplicate.as_slice(),
        indefinite.as_slice(),
        deep.as_slice(),
        many.as_slice(),
    ] {
        let bytes = assertion(Some(extension));
        assert!(bytes.len() < 4096);
        assert!(AuthenticatorData::<Authentication>::try_from(bytes.as_slice()).is_ok());
    }
    for malformed in [&[0xa1][..], &[0xa1, 0x61, b'x'], &[0x81]] {
        let bytes = assertion(Some(malformed));
        assert!(AuthenticatorData::<Authentication>::try_from(bytes.as_slice()).is_err());
    }
}

#[test]
fn upstream_cose_parser_loses_duplicate_key_evidence() {
    let mut bytes = vec![0; 32];
    bytes.push(0x45); // UP/UV/AT.
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(&[0; 16]); // AAGUID.
    bytes.extend_from_slice(&[0, 1, 42]); // One-byte credential ID.
    // Duplicate integer key 1. This is not a usable public key; no verifier is invoked.
    bytes.extend_from_slice(&[0xa2, 0x01, 0x02, 0x18, 0x01, 0x03]);
    let parsed = AuthenticatorData::<Registration>::try_from(bytes.as_slice()).unwrap();
    assert!(parsed.acd.is_some());
    let mut truncated = bytes[..55].to_vec();
    truncated[53] = 0xff;
    truncated[54] = 0xff; // Declares unavailable credential bytes.
    assert!(AuthenticatorData::<Registration>::try_from(truncated.as_slice()).is_err());
}
