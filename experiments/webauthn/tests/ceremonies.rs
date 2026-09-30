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
