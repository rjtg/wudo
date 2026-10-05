use super::*;
use std::{fs, os::unix::fs::PermissionsExt};
use webauthn_authenticator_rs::{AuthenticatorBackendHashedClientData, softpasskey::SoftPasskey};
const ORIGIN: &str = "https://wudo.example.test";
fn setup() -> (tempfile::TempDir, Store, Enrollment) {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut store = Store::initialize(dir.path()).unwrap();
    store.configure_installation(ORIGIN).unwrap();
    let enrollment = Enrollment::new(&store).unwrap();
    (dir, store, enrollment)
}
fn bytes(request: &wire::Request<'_>, endpoint: wire::Endpoint) -> Vec<u8> {
    let mut out = vec![0; wire::MAX_PAYLOAD];
    let n = wire::encode_request(&mut out, request, endpoint).unwrap();
    out.truncate(n);
    out
}
fn call(
    e: &mut Enrollment,
    s: &mut Store,
    request: &wire::Request<'_>,
    endpoint: wire::Endpoint,
    now: Instant,
) -> Result<Vec<u8>> {
    e.request(&bytes(request, endpoint), endpoint, s, now)
}
fn open(
    e: &mut Enrollment,
    s: &mut Store,
    name: &str,
    mode: wire::Mode,
    now: Instant,
) -> (
    wire::EnrollmentId,
    wire::Request<'static>,
    wudo_store::UserId,
) {
    let user = s.create_user(name, name).unwrap();
    let request = wire::Request::EnrollmentOpen(wire::EnrollmentOpen {
        user_id: wire::UserId(*user.id.as_bytes()),
        mode,
    });
    let reply = call(e, s, &request, wire::Endpoint::Admin, now).unwrap();
    let wire::Response::Opened(v) =
        wire::decode_response(&reply, &request, wire::Endpoint::Admin).unwrap()
    else {
        panic!("opened")
    };
    (
        v.enrollment_id,
        match v.ticket {
            Some(ticket) => wire::Request::RegistrationBegin(wire::RegistrationBegin { ticket }),
            None => wire::Request::RegistrationBeginInsecure,
        },
        user.id,
    )
}
fn finish(
    e: &mut Enrollment,
    s: &mut Store,
    begin: &wire::Request<'_>,
    now: Instant,
    uv: bool,
    origin: &str,
) -> (Vec<u8>, Vec<u8>) {
    let reply = call(e, s, begin, wire::Endpoint::Web, now).unwrap();
    let wire::Response::RegistrationChallenge(v) =
        wire::decode_response(&reply, begin, wire::Endpoint::Web).unwrap()
    else {
        panic!("challenge")
    };
    let o = v.options;
    let b64 = |b: &[u8]| Base64UrlSafeData::from(b.to_vec());
    let options: CreationChallengeResponse = serde_json::from_value(serde_json::json!({"publicKey": {
        "rp":{"id":o.rp.id.0,"name":o.rp.name.0},
        "user":{"id":b64(&o.user.id.0),"name":o.user.name.0,"displayName":o.user.display_name.0},
        "challenge":b64(&o.challenge.0),"timeout":o.timeout_ms.0,
        "pubKeyCredParams":o.algorithms.0.iter().map(|a|serde_json::json!({"type":"public-key","alg":a})).collect::<Vec<_>>(),
        "excludeCredentials":o.exclude_credentials.0.iter().map(|id|serde_json::json!({"type":"public-key","id":b64(id.0)})).collect::<Vec<_>>(),
        "authenticatorSelection":{"userVerification":if uv {"required"} else {"preferred"},"residentKey":"discouraged","requireResidentKey":false},
        "attestation":"none",
        "extensions":{"credentialProtectionPolicy":"userVerificationRequired","enforceCredentialProtectionPolicy":false,"uvm":true,"credProps":true}
    }})).unwrap();
    let data = serde_json::to_vec(&serde_json::json!({"type":"webauthn.create","challenge":options.public_key.challenge,"origin":origin})).unwrap();
    let mut client = SoftPasskey::new(true);
    let result = client
        .perform_register(
            openssl::sha::sha256(&data).to_vec(),
            options.public_key,
            120000,
        )
        .unwrap();
    let request = wire::Request::RegistrationFinish(wire::RegistrationFinish {
        ceremony_id: v.ceremony_id,
        credential_id: wire::Blob(result.raw_id.as_ref()),
        client_data: wire::Blob(&data),
        attestation_object: wire::Blob(result.response.attestation_object.as_ref()),
        client_extensions: wire::RegistrationExtensions {
            resident_key: None,
            cred_protect: None,
        },
    });
    (
        bytes(&request, wire::Endpoint::Web),
        result.raw_id.as_ref().to_vec(),
    )
}
#[test]
fn confirm_requires_exact_candidate_and_durable_activation() {
    let (dir, mut s, mut e) = setup();
    let now = Instant::now();
    let (id, begin, user) = open(&mut e, &mut s, "alice", wire::Mode::Confirm, now);
    let (payload, key) = finish(&mut e, &mut s, &begin, now, true, ORIGIN);
    let job = e.take_finish(&payload, wire::Endpoint::Web, now).unwrap();
    assert!(matches!(
        e.take_finish(&payload, wire::Endpoint::Web, now),
        Err(Error::Unavailable)
    ));
    assert_eq!(
        e.complete(job.run(), &mut s, now).unwrap(),
        wire::RegistrationState::PendingApproval
    );
    assert!(
        s.credential_for_authentication(user, &key)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        call(&mut e, &mut s, &begin, wire::Endpoint::Web, now),
        Err(Error::Busy)
    ));
    let inspect = wire::Request::EnrollmentInspect(wire::EnrollmentRef { enrollment_id: id });
    let reply = call(&mut e, &mut s, &inspect, wire::Endpoint::Admin, now).unwrap();
    let wire::Response::CandidateInspection(candidate) =
        wire::decode_response(&reply, &inspect, wire::Endpoint::Admin).unwrap()
    else {
        panic!("candidate")
    };
    assert!(candidate.credential_id.0 == key);
    assert!(candidate.fingerprint.0 == openssl::sha::sha256(&key));
    let wrong = wire::Request::EnrollmentApprove(wire::EnrollmentApprove {
        enrollment_id: id,
        candidate_id: wire::CandidateId([0; 32]),
    });
    assert!(matches!(
        call(&mut e, &mut s, &wrong, wire::Endpoint::Admin, now),
        Err(Error::Unavailable)
    ));
    let approve = wire::Request::EnrollmentApprove(wire::EnrollmentApprove {
        enrollment_id: id,
        candidate_id: candidate.candidate_id,
    });
    call(&mut e, &mut s, &approve, wire::Endpoint::Admin, now).unwrap();
    assert!(matches!(
        call(&mut e, &mut s, &approve, wire::Endpoint::Admin, now),
        Err(Error::Unavailable)
    ));
    drop(s);
    let s = Store::open(dir.path()).unwrap();
    assert!(
        s.credential_for_authentication(user, &key)
            .unwrap()
            .is_some()
    );
}
#[test]
fn insecure_activates_once_and_restart_loses_pending_state() {
    let (_dir, mut s, mut e) = setup();
    let now = Instant::now();
    let (_, begin, user) = open(&mut e, &mut s, "alice", wire::Mode::Insecure, now);
    let (payload, key) = finish(&mut e, &mut s, &begin, now, true, ORIGIN);
    let job = e.take_finish(&payload, wire::Endpoint::Web, now).unwrap();
    assert_eq!(
        e.complete(job.run(), &mut s, now).unwrap(),
        wire::RegistrationState::Active
    );
    assert!(
        s.credential_for_authentication(user, &key)
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        call(&mut e, &mut s, &begin, wire::Endpoint::Web, now),
        Err(Error::Unavailable)
    ));
    assert!(matches!(
        e.take_finish(&payload, wire::Endpoint::Web, now),
        Err(Error::Unavailable)
    ));
    let (_dir2, _s2, mut restarted) = setup();
    assert!(matches!(
        restarted.take_finish(&payload, wire::Endpoint::Web, now),
        Err(Error::Unavailable)
    ));
}
#[test]
fn cancellation_expiry_and_failure_never_activate() {
    for scenario in 0..5 {
        let (_dir, mut s, mut e) = setup();
        let now = Instant::now();
        let (id, begin, user) = open(&mut e, &mut s, "alice", wire::Mode::Insecure, now);
        let (payload, key) = finish(
            &mut e,
            &mut s,
            &begin,
            now,
            scenario != 2,
            if scenario == 3 {
                "https://other.example.test"
            } else {
                ORIGIN
            },
        );
        let job = e.take_finish(&payload, wire::Endpoint::Web, now).unwrap();
        if scenario == 0 {
            call(
                &mut e,
                &mut s,
                &wire::Request::EnrollmentCancel(wire::EnrollmentRef { enrollment_id: id }),
                wire::Endpoint::Admin,
                now,
            )
            .unwrap();
        }
        let later = if scenario == 1 {
            now + CEREMONY
        } else if scenario == 4 {
            now + WINDOW
        } else {
            now
        };
        assert!(e.complete(job.run(), &mut s, later).is_err());
        assert!(
            s.credential_for_authentication(user, &key)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            e.take_finish(&payload, wire::Endpoint::Web, later),
            Err(Error::Unavailable)
        ));
        if matches!(scenario, 1..=3) {
            let (fresh, _) = finish(&mut e, &mut s, &begin, later, true, ORIGIN);
            let job = e.take_finish(&fresh, wire::Endpoint::Web, later).unwrap();
            assert_eq!(
                e.complete(job.run(), &mut s, later).unwrap(),
                wire::RegistrationState::Active
            );
        }
    }
}
#[test]
fn worker_capacity_survives_cancellation_and_busy_consumes_challenge() {
    let (_dir, mut s, mut e) = setup();
    let now = Instant::now();
    let mut jobs = Vec::new();
    for name in ["alice", "bob"] {
        let (id, begin, _) = open(&mut e, &mut s, name, wire::Mode::Confirm, now);
        let (payload, _) = finish(&mut e, &mut s, &begin, now, true, ORIGIN);
        jobs.push(e.take_finish(&payload, wire::Endpoint::Web, now).unwrap());
        call(
            &mut e,
            &mut s,
            &wire::Request::EnrollmentCancel(wire::EnrollmentRef { enrollment_id: id }),
            wire::Endpoint::Admin,
            now,
        )
        .unwrap();
    }
    let (_, begin, _) = open(&mut e, &mut s, "carol", wire::Mode::Confirm, now);
    let (payload, _) = finish(&mut e, &mut s, &begin, now, true, ORIGIN);
    assert!(matches!(
        e.take_finish(&payload, wire::Endpoint::Web, now),
        Err(Error::Busy)
    ));
    assert!(matches!(
        e.take_finish(&payload, wire::Endpoint::Web, now),
        Err(Error::Unavailable)
    ));
    drop(jobs);
    let (payload, _) = finish(&mut e, &mut s, &begin, now, true, ORIGIN);
    assert!(e.take_finish(&payload, wire::Endpoint::Web, now).is_ok());
}
#[test]
fn endpoint_invalid_and_mismatched_id_checks() {
    let (_dir, mut s, mut e) = setup();
    let now = Instant::now();
    let (_, begin, _) = open(&mut e, &mut s, "alice", wire::Mode::Insecure, now);
    let (payload, _) = finish(&mut e, &mut s, &begin, now, true, ORIGIN);
    assert!(matches!(
        e.take_finish(&payload, wire::Endpoint::Admin, now),
        Err(Error::NotPermitted)
    ));
    assert!(
        e.take_finish(&payload[..payload.len() - 1], wire::Endpoint::Web, now)
            .is_err()
    );
    let wire::Request::RegistrationFinish(mut changed) =
        wire::decode_request(&payload, wire::Endpoint::Web).unwrap()
    else {
        panic!("finish")
    };
    changed.credential_id = wire::Blob(&[42; 32]);
    let changed = bytes(
        &wire::Request::RegistrationFinish(changed),
        wire::Endpoint::Web,
    );
    let job = e.take_finish(&changed, wire::Endpoint::Web, now).unwrap();
    assert!(matches!(
        e.complete(job.run(), &mut s, now),
        Err(Error::VerificationFailed)
    ));
}

#[test]
fn option_projection_rejects_unexpected_library_profiles() {
    let (_dir, mut store, e) = setup();
    let user = store.create_user("alice", "Alice").unwrap();
    let (options, _) = e
        .verifier
        .start_passkey_registration(
            Uuid::from_bytes(*user.id.as_bytes()),
            "alice",
            "Alice",
            None,
        )
        .unwrap();
    let projected = adapter::options(&options, 120000).unwrap();
    assert!(projected.challenge.0.as_slice() == options.public_key.challenge.as_ref());
    assert_eq!(projected.algorithms.0, vec![-7, -257]);
    for mutation in 0..6 {
        let mut changed = options.clone();
        match mutation {
            0 => {
                changed
                    .public_key
                    .authenticator_selection
                    .as_mut()
                    .unwrap()
                    .user_verification = webauthn_rs_proto::UserVerificationPolicy::Preferred
            }
            1 => {
                changed
                    .public_key
                    .authenticator_selection
                    .as_mut()
                    .unwrap()
                    .resident_key = Some(webauthn_rs_proto::ResidentKeyRequirement::Required)
            }
            2 => {
                changed
                    .public_key
                    .extensions
                    .as_mut()
                    .unwrap()
                    .hmac_create_secret = Some(true)
            }
            3 => {
                changed.public_key.attestation =
                    Some(webauthn_rs_proto::AttestationConveyancePreference::Direct)
            }
            4 => changed.public_key.challenge = vec![1; 31].into(),
            _ => changed.public_key.timeout = Some(1),
        }
        assert!(adapter::options(&changed, 120000).is_err());
    }
}
#[test]
fn windows_tickets_capacity_and_approval_expiry() {
    let (_dir, mut s, mut e) = setup();
    let now = Instant::now();
    let (id, begin, user) = open(&mut e, &mut s, "alice", wire::Mode::Confirm, now);
    let duplicate = wire::Request::EnrollmentOpen(wire::EnrollmentOpen {
        user_id: wire::UserId(*user.as_bytes()),
        mode: wire::Mode::Confirm,
    });
    assert!(matches!(
        call(&mut e, &mut s, &duplicate, wire::Endpoint::Admin, now),
        Err(Error::Busy)
    ));
    let wrong_ticket = wire::Request::RegistrationBegin(wire::RegistrationBegin {
        ticket: wire::Ticket([0; 32]),
    });
    assert!(matches!(
        call(&mut e, &mut s, &wrong_ticket, wire::Endpoint::Web, now),
        Err(Error::Unavailable)
    ));
    let (payload, key) = finish(&mut e, &mut s, &begin, now, true, ORIGIN);
    let job = e.take_finish(&payload, wire::Endpoint::Web, now).unwrap();
    e.complete(job.run(), &mut s, now).unwrap();
    let inspect = wire::Request::EnrollmentInspect(wire::EnrollmentRef { enrollment_id: id });
    let reply = call(&mut e, &mut s, &inspect, wire::Endpoint::Admin, now).unwrap();
    let wire::Response::CandidateInspection(v) =
        wire::decode_response(&reply, &inspect, wire::Endpoint::Admin).unwrap()
    else {
        panic!("candidate")
    };
    let approve = wire::Request::EnrollmentApprove(wire::EnrollmentApprove {
        enrollment_id: id,
        candidate_id: v.candidate_id,
    });
    assert!(matches!(
        call(
            &mut e,
            &mut s,
            &approve,
            wire::Endpoint::Admin,
            now + WINDOW
        ),
        Err(Error::Unavailable)
    ));
    assert!(
        s.credential_for_authentication(user, &key)
            .unwrap()
            .is_none()
    );
    for name in ["bob", "carol", "dave", "eve"] {
        open(&mut e, &mut s, name, wire::Mode::Confirm, now + WINDOW);
    }
    assert!(matches!(
        call(
            &mut e,
            &mut s,
            &duplicate,
            wire::Endpoint::Admin,
            now + WINDOW
        ),
        Err(Error::Busy)
    ));
    assert!(
        call(
            &mut e,
            &mut s,
            &duplicate,
            wire::Endpoint::Admin,
            now + WINDOW + WINDOW
        )
        .is_ok()
    );
}
#[test]
fn durable_activation_failure_never_reports_success() {
    let (dir, mut s, mut e) = setup();
    let now = Instant::now();
    let (_, begin, user) = open(&mut e, &mut s, "alice", wire::Mode::Insecure, now);
    let (payload, key) = finish(&mut e, &mut s, &begin, now, true, ORIGIN);
    let job = e.take_finish(&payload, wire::Endpoint::Web, now).unwrap();
    // Hold another valid writer's lock; the store must fail closed on timeout.
    let blocker = rusqlite::Connection::open(dir.path().join("identity.sqlite3")).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(matches!(
        e.complete(job.run(), &mut s, now),
        Err(Error::InternalError)
    ));
    blocker.execute_batch("ROLLBACK").unwrap();
    drop(s);
    let s = Store::open(dir.path()).unwrap();
    assert!(
        s.credential_for_authentication(user, &key)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        e.take_finish(&payload, wire::Endpoint::Web, now),
        Err(Error::Unavailable)
    ));
}

#[test]
fn unconfigured_store_cannot_create_enrollment_verifier() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let store = Store::initialize(dir.path()).unwrap();
    assert!(matches!(Enrollment::new(&store), Err(Error::Unavailable)));
}

#[test]
fn reset_invalidates_running_and_pending_work_even_at_same_origin() {
    let (_dir, mut s, mut e) = setup();
    let now = Instant::now();
    let (id, begin, _) = open(&mut e, &mut s, "alice", wire::Mode::Insecure, now);
    let (payload, key) = finish(&mut e, &mut s, &begin, now, true, ORIGIN);
    let job = e.take_finish(&payload, wire::Endpoint::Web, now).unwrap();
    e.invalidate();
    s.reset_installation(ORIGIN).unwrap();
    e.reload(&s).unwrap();
    assert_eq!(e.workers.load(Ordering::Acquire), 1);
    let result = job.run();
    assert_eq!(e.workers.load(Ordering::Acquire), 1);
    assert!(matches!(
        e.complete(result, &mut s, now),
        Err(Error::Unavailable)
    ));
    assert_eq!(e.workers.load(Ordering::Acquire), 0);
    assert!(!s.credential_id_exists(&key).unwrap());
    let inspect = wire::Request::EnrollmentInspect(wire::EnrollmentRef { enrollment_id: id });
    assert!(matches!(
        call(&mut e, &mut s, &inspect, wire::Endpoint::Admin, now),
        Err(Error::Unavailable)
    ));
}

#[test]
fn opportunities_reserve_global_credential_capacity() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    let (_dir, mut store, mut engine) = setup();
    let owner = store.create_user("history", "History").unwrap();
    for _ in 0..wudo_store::MAX_CREDENTIALS - 1 {
        let (options, state) = engine
            .verifier
            .start_passkey_registration(
                Uuid::from_bytes(*owner.id.as_bytes()),
                "history",
                "History",
                None,
            )
            .unwrap();
        let mut client = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let response = client
            .do_registration(Url::parse(ORIGIN).unwrap(), options)
            .unwrap();
        let key = engine
            .verifier
            .finish_passkey_registration(&response, &state)
            .unwrap();
        store.activate_credential(owner.id, &key).unwrap();
        store.revoke_credential(key.cred_id().as_ref()).unwrap();
    }
    assert_eq!(store.remaining_credential_capacity().unwrap(), 1);
    let now = Instant::now();
    let (id, _, _) = open(&mut engine, &mut store, "alice", wire::Mode::Confirm, now);
    let user = store.create_user("bob", "Bob").unwrap();
    let req = wire::Request::EnrollmentOpen(wire::EnrollmentOpen {
        user_id: wire::UserId(*user.id.as_bytes()),
        mode: wire::Mode::Confirm,
    });
    assert!(matches!(
        call(&mut engine, &mut store, &req, wire::Endpoint::Admin, now),
        Err(Error::Unavailable)
    ));
    call(
        &mut engine,
        &mut store,
        &wire::Request::EnrollmentCancel(wire::EnrollmentRef { enrollment_id: id }),
        wire::Endpoint::Admin,
        now,
    )
    .unwrap();
    assert!(call(&mut engine, &mut store, &req, wire::Endpoint::Admin, now).is_ok());
}

#[test]
fn retained_revocation_blocks_late_verification_and_candidate_approval() {
    for pending_approval in [false, true] {
        let (_dir, mut s, mut e) = setup();
        let now = Instant::now();
        let mode = if pending_approval {
            wire::Mode::Confirm
        } else {
            wire::Mode::Insecure
        };
        let (enrollment_id, begin, user) = open(&mut e, &mut s, "alice", mode, now);
        let (payload, id) = finish(&mut e, &mut s, &begin, now, true, ORIGIN);
        let verified = e
            .take_finish(&payload, wire::Endpoint::Web, now)
            .unwrap()
            .run();
        let key = verified.result.as_ref().unwrap().clone();
        if pending_approval {
            e.complete(verified, &mut s, now).unwrap();
            let inspect = wire::Request::EnrollmentInspect(wire::EnrollmentRef { enrollment_id });
            let reply = call(&mut e, &mut s, &inspect, wire::Endpoint::Admin, now).unwrap();
            let wire::Response::CandidateInspection(candidate) =
                wire::decode_response(&reply, &inspect, wire::Endpoint::Admin).unwrap()
            else {
                panic!("candidate");
            };
            // Model a competing durable writer before approval. Retaining the ID
            // must prevent the verified snapshot from reactivating it.
            s.activate_credential(user, &key).unwrap();
            s.revoke_owned_credential(user, &id).unwrap().unwrap();
            let approve = wire::Request::EnrollmentApprove(wire::EnrollmentApprove {
                enrollment_id,
                candidate_id: candidate.candidate_id,
            });
            assert!(call(&mut e, &mut s, &approve, wire::Endpoint::Admin, now).is_err());
        } else {
            s.activate_credential(user, &key).unwrap();
            s.revoke_owned_credential(user, &id).unwrap().unwrap();
            assert!(matches!(
                e.complete(verified, &mut s, now),
                Err(Error::Unavailable)
            ));
        }
        assert!(s.inspect_credential(user, &id).unwrap().unwrap().revoked);
        assert!(
            s.credential_for_authentication(user, &id)
                .unwrap()
                .is_none()
        );
    }
}
