//! Synthetic credentials only. SoftPasskey simulates UV, not human verification.
use url::Url;
use uuid::Uuid;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
use webauthn_rs::prelude::*;
use webauthn_rs_proto::UserVerificationPolicy;

const ORIGIN: &str = "https://wudo.example.test";
const RP: &str = "wudo.example.test";

fn verifier() -> Webauthn {
    WebauthnBuilder::new(RP, &Url::parse(ORIGIN).unwrap())
        .unwrap()
        .allow_subdomains(false)
        .allow_any_port(false)
        .build()
        .unwrap()
}

fn registration(server: &Webauthn) -> (CreationChallengeResponse, PasskeyRegistration) {
    server
        .start_passkey_registration(Uuid::new_v4(), "synthetic", "Synthetic test", None)
        .unwrap()
}

fn enrolled(server: &Webauthn) -> (WebauthnAuthenticator<SoftPasskey>, Passkey) {
    // Upstream's software authenticator deliberately fakes the UV flag for tests.
    let mut client = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (options, state) = registration(server);
    let response = client
        .do_registration(Url::parse(ORIGIN).unwrap(), options)
        .unwrap();
    let key = server
        .finish_passkey_registration(&response, &state)
        .unwrap();
    (client, key)
}

#[test]
fn registration_and_authentication_round_trip() {
    let server = verifier();
    let (mut client, mut key) = enrolled(&server);
    let (options, state) = server
        .start_passkey_authentication(std::slice::from_ref(&key))
        .unwrap();
    assert_eq!(
        options.public_key.user_verification,
        UserVerificationPolicy::Required
    );
    let response = client
        .do_authentication(Url::parse(ORIGIN).unwrap(), options)
        .unwrap();
    let result = server
        .finish_passkey_authentication(&response, &state)
        .unwrap();
    assert!(result.user_verified());
    assert_eq!(key.update_credential(&result), Some(true));
}

#[test]
fn registration_rejects_another_challenge() {
    let server = verifier();
    let mut client = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (options, _) = registration(&server);
    let (_, wrong_state) = registration(&server);
    let response = client
        .do_registration(Url::parse(ORIGIN).unwrap(), options)
        .unwrap();
    assert!(
        server
            .finish_passkey_registration(&response, &wrong_state)
            .is_err()
    );
}

#[test]
fn signed_wrong_origins_are_rejected_in_both_ceremonies() {
    for wrong_origin in [
        "https://sub.wudo.example.test",
        "https://wudo.example.test:8443",
    ] {
        let server = verifier();
        let (mut client, key) = enrolled(&server);
        let (options, state) = registration(&server);
        let response = client
            .do_registration(Url::parse(wrong_origin).unwrap(), options)
            .unwrap();
        assert!(
            server
                .finish_passkey_registration(&response, &state)
                .is_err()
        );
        let (options, state) = server.start_passkey_authentication(&[key]).unwrap();
        let response = client
            .do_authentication(Url::parse(wrong_origin).unwrap(), options)
            .unwrap();
        assert!(
            server
                .finish_passkey_authentication(&response, &state)
                .is_err()
        );
    }
}

#[test]
fn signed_responses_without_uv_are_rejected() {
    let server = verifier();
    let (mut client, key) = enrolled(&server);
    let (mut options, state) = registration(&server);
    options
        .public_key
        .authenticator_selection
        .as_mut()
        .unwrap()
        .user_verification = UserVerificationPolicy::Preferred;
    let response = client
        .do_registration(Url::parse(ORIGIN).unwrap(), options)
        .unwrap();
    assert!(
        server
            .finish_passkey_registration(&response, &state)
            .is_err()
    );
    let (mut options, state) = server.start_passkey_authentication(&[key]).unwrap();
    options.public_key.user_verification = UserVerificationPolicy::Preferred;
    let response = client
        .do_authentication(Url::parse(ORIGIN).unwrap(), options)
        .unwrap();
    assert!(
        server
            .finish_passkey_authentication(&response, &state)
            .is_err()
    );
}

#[test]
fn assertion_rejects_challenge_key_and_signature_substitution() {
    let server = verifier();
    let (mut client, key) = enrolled(&server);
    let (_, other_key) = enrolled(&server);
    let (options, state) = server
        .start_passkey_authentication(std::slice::from_ref(&key))
        .unwrap();
    let (_, other_challenge) = server.start_passkey_authentication(&[key]).unwrap();
    let (_, other_identity) = server.start_passkey_authentication(&[other_key]).unwrap();
    let mut response = client
        .do_authentication(Url::parse(ORIGIN).unwrap(), options)
        .unwrap();
    assert!(
        server
            .finish_passkey_authentication(&response, &other_challenge)
            .is_err()
    );
    assert!(
        server
            .finish_passkey_authentication(&response, &other_identity)
            .is_err()
    );
    let mut signature = response.response.signature.as_ref().to_vec();
    signature[0] ^= 1;
    response.response.signature = signature.into();
    assert!(
        server
            .finish_passkey_authentication(&response, &state)
            .is_err()
    );
}

#[test]
fn signed_wrong_rp_hash_is_rejected() {
    let server = verifier();
    let (mut client, key) = enrolled(&server);
    let (mut options, state) = server.start_passkey_authentication(&[key]).unwrap();
    // The synthetic backend signs with its key even for this changed RP.
    // No cryptographic bytes are manufactured by the test itself.
    options.public_key.rp_id = "example.test".into();
    let response = client
        .do_authentication(Url::parse(ORIGIN).unwrap(), options)
        .unwrap();
    assert!(
        server
            .finish_passkey_authentication(&response, &state)
            .is_err()
    );
}

#[test]
fn verifier_state_is_not_a_single_use_authorization_store() {
    let server = verifier();
    let (mut client, key) = enrolled(&server);
    let (options, state) = server.start_passkey_authentication(&[key]).unwrap();
    let response = client
        .do_authentication(Url::parse(ORIGIN).unwrap(), options)
        .unwrap();
    assert!(
        server
            .finish_passkey_authentication(&response, &state)
            .is_ok()
    );
    // This is an API characterization, not desired daemon behavior. Wudo must
    // consume its own pending record atomically before calling the verifier.
    assert!(
        server
            .finish_passkey_authentication(&response, &state)
            .is_ok()
    );
}

#[test]
fn builder_is_not_wudo_configuration_validation() {
    // These are legal library configurations but excluded by Wudo's policy.
    for (rp, origin) in [("example.test", ORIGIN), (RP, "http://wudo.example.test")] {
        assert!(WebauthnBuilder::new(rp, &Url::parse(origin).unwrap()).is_ok());
    }
}

#[test]
fn public_credential_serialization_survives_reload_and_metadata_update() {
    let server = verifier();
    let (mut client, key) = enrolled(&server);
    let saved = serde_json::to_vec(&key).unwrap();
    assert!(saved.len() <= 16 * 1024);
    let mut restored: Passkey = serde_json::from_slice(&saved).unwrap();
    assert!(restored.cred_id() == key.cred_id());
    let (options, state) = server
        .start_passkey_authentication(std::slice::from_ref(&restored))
        .unwrap();
    let response = client
        .do_authentication(Url::parse(ORIGIN).unwrap(), options)
        .unwrap();
    let result = server
        .finish_passkey_authentication(&response, &state)
        .unwrap();
    assert_eq!(restored.update_credential(&result), Some(true));
    let updated = serde_json::to_vec(&restored).unwrap();
    assert!(updated.len() <= 16 * 1024);
    assert!(saved != updated);
    let reloaded: Passkey = serde_json::from_slice(&updated).unwrap();
    let (options, state) = server.start_passkey_authentication(&[reloaded]).unwrap();
    let response = client
        .do_authentication(Url::parse(ORIGIN).unwrap(), options)
        .unwrap();
    assert!(
        server
            .finish_passkey_authentication(&response, &state)
            .is_ok()
    );
}

#[test]
fn verifier_registration_identity_comes_from_attestation_not_outer_id() {
    let server = verifier();
    let mut client = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (options, state) = registration(&server);
    let mut response = client
        .do_registration(Url::parse(ORIGIN).unwrap(), options)
        .unwrap();
    let actual_id = response.raw_id.clone();
    response.raw_id = vec![0x42; 32].into();
    response.id = "untrusted-outer-id".into();
    let key = server
        .finish_passkey_registration(&response, &state)
        .unwrap();
    assert!(key.cred_id().as_ref() == actual_id.as_ref());
    assert!(key.cred_id().as_ref() != response.raw_id.as_ref());
    // Wudo's adapter must compare the verified ID with the wire credential_id
    // before binding a candidate, displaying its fingerprint or storing it.
}

#[test]
fn signed_responses_fit_wudo_wire_without_changing_signed_bytes() {
    use wudo_protocol::v2 as wire;
    let server = verifier();
    use webauthn_authenticator_rs::AuthenticatorBackendHashedClientData;
    let mut client = SoftPasskey::new(true);
    let (options, state) = registration(&server);
    // Construct the approved client-data profile BEFORE signing its hash.
    let data = serde_json::to_vec(&serde_json::json!({
        "type":"webauthn.create", "challenge":options.public_key.challenge, "origin":ORIGIN
    }))
    .unwrap();
    let mut response = client
        .perform_register(
            openssl::sha::sha256(&data).to_vec(),
            options.public_key,
            120000,
        )
        .unwrap();
    response.response.client_data_json = data.into();
    let request = wire::Request::RegistrationFinish(wire::RegistrationFinish {
        ceremony_id: wire::CeremonyId([1; 32]),
        credential_id: wire::Blob(response.raw_id.as_ref()),
        client_data: wire::Blob(response.response.client_data_json.as_ref()),
        attestation_object: wire::Blob(response.response.attestation_object.as_ref()),
        client_extensions: wire::RegistrationExtensions {
            resident_key: None,
            cred_protect: None,
        },
    });
    let mut bytes = vec![0; wire::MAX_PAYLOAD];
    let n = wire::encode_request(&mut bytes, &request, wire::Endpoint::Web).unwrap();
    let wire::Request::RegistrationFinish(decoded) =
        wire::decode_request(&bytes[..n], wire::Endpoint::Web).unwrap()
    else {
        panic!("wrong variant")
    };
    assert!(decoded.client_data.0 == response.response.client_data_json.as_ref());
    response.raw_id = decoded.credential_id.0.to_vec().into();
    response.response.client_data_json = decoded.client_data.0.to_vec().into();
    response.response.attestation_object = decoded.attestation_object.0.to_vec().into();
    let key = server
        .finish_passkey_registration(&response, &state)
        .unwrap();
    let (options, state) = server.start_passkey_authentication(&[key]).unwrap();
    let data = serde_json::to_vec(&serde_json::json!({
        "type":"webauthn.get", "challenge":options.public_key.challenge, "origin":ORIGIN
    }))
    .unwrap();
    let mut response = client
        .perform_auth(
            openssl::sha::sha256(&data).to_vec(),
            options.public_key,
            120000,
        )
        .unwrap();
    response.response.client_data_json = data.into();
    assert!(response.response.user_handle.is_none());
    let request = wire::Request::ActionFinish(wire::ActionFinish {
        ceremony_id: wire::CeremonyId([2; 32]),
        credential_id: wire::Blob(response.raw_id.as_ref()),
        client_data: wire::Blob(response.response.client_data_json.as_ref()),
        authenticator_data: wire::Blob(response.response.authenticator_data.as_ref()),
        signature: wire::Blob(response.response.signature.as_ref()),
        user_handle: None,
    });
    let n = wire::encode_request(&mut bytes, &request, wire::Endpoint::Web).unwrap();
    let wire::Request::ActionFinish(decoded) =
        wire::decode_request(&bytes[..n], wire::Endpoint::Web).unwrap()
    else {
        panic!("wrong variant")
    };
    assert!(decoded.client_data.0 == response.response.client_data_json.as_ref());
    response.raw_id = decoded.credential_id.0.to_vec().into();
    response.response.client_data_json = decoded.client_data.0.to_vec().into();
    response.response.authenticator_data = decoded.authenticator_data.0.to_vec().into();
    response.response.signature = decoded.signature.0.to_vec().into();
    assert!(
        server
            .finish_passkey_authentication(&response, &state)
            .is_ok()
    );
}

#[test]
fn upstream_clientdata_null_token_binding_is_outside_wudo_profile() {
    use wudo_protocol::v2 as wire;
    let server = verifier();
    let mut client = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (options, state) = registration(&server);
    let response = client
        .do_registration(Url::parse(ORIGIN).unwrap(), options)
        .unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(response.response.client_data_json.as_ref()).unwrap();
    assert!(
        value
            .get("tokenBinding")
            .is_some_and(serde_json::Value::is_null)
    );
    let request = wire::Request::RegistrationFinish(wire::RegistrationFinish {
        ceremony_id: wire::CeremonyId([1; 32]),
        credential_id: wire::Blob(response.raw_id.as_ref()),
        client_data: wire::Blob(response.response.client_data_json.as_ref()),
        attestation_object: wire::Blob(response.response.attestation_object.as_ref()),
        client_extensions: wire::RegistrationExtensions {
            resident_key: None,
            cred_protect: None,
        },
    });
    assert!(matches!(
        wire::encode_request(
            &mut vec![0; wire::MAX_PAYLOAD],
            &request,
            wire::Endpoint::Web
        ),
        Err(wire::Error::InvalidRequest)
    ));
    assert!(
        server
            .finish_passkey_registration(&response, &state)
            .is_ok()
    );
}
