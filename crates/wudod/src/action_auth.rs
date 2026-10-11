//! Single-use action authentication and admission, owned by the serialized state worker.
//! Viewing tokens never enter this state machine. Do not log assertions or handles.
use base64::Engine;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use webauthn_rs::prelude::*;
use webauthn_rs_proto::AuthenticatorAssertionResponseRaw;
use wudo_protocol::v2::{self as wire, Error, Result};
use wudo_store::{AuthenticationSnapshot, Store, UserId};
const CEREMONY: Duration = Duration::from_secs(120);
struct Pending {
    lease: crate::ceremony_budget::Lease,
    id: wire::CeremonyId,
    user: UserId,
    action: String,
    revision: [u8; 32],
    operation: crate::integrations::ConfiguredOperation,
    deadline: Instant,
    state: Option<(PasskeyAuthentication, Vec<AuthenticationSnapshot>)>,
}
pub struct Actions {
    budgets: crate::ceremony_budget::Budgets,
    verifier: Arc<Webauthn>,
    origin: wire::InstallationOrigin,
    generation: [u8; 32],
    valid: bool,
    pending: Vec<Pending>,
    workers: Arc<AtomicUsize>,
}
struct Permit(Arc<AtomicUsize>);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
pub struct Verification {
    _ceremony: crate::ceremony_budget::Lease,
    _crypto: crate::ceremony_budget::Lease,
    id: wire::CeremonyId,
    verifier: Arc<Webauthn>,
    state: PasskeyAuthentication,
    response: PublicKeyCredential,
    snapshot: AuthenticationSnapshot,
    _permit: Permit,
}
pub struct Verified {
    _ceremony: crate::ceremony_budget::Lease,
    _crypto: crate::ceremony_budget::Lease,
    id: wire::CeremonyId,
    result: Result<AuthenticationResult>,
    snapshot: AuthenticationSnapshot,
    _permit: Permit,
}
impl Verification {
    pub fn run(self) -> Verified {
        let result = self
            .verifier
            .finish_passkey_authentication(&self.response, &self.state)
            .map_err(|_| Error::VerificationFailed);
        Verified {
            _ceremony: self._ceremony,
            _crypto: self._crypto,
            id: self.id,
            result,
            snapshot: self.snapshot,
            _permit: self._permit,
        }
    }
}
fn store_error(e: wudo_store::Error) -> Error {
    match e {
        wudo_store::Error::Conflict
        | wudo_store::Error::InvalidInput
        | wudo_store::Error::Capacity => Error::Unavailable,
        _ => Error::InternalError,
    }
}
fn random() -> Result<[u8; 32]> {
    let mut b = [0; 32];
    getrandom::fill(&mut b).map_err(|_| Error::InternalError)?;
    Ok(b)
}
fn encode(q: &wire::Request<'_>, r: &wire::Response<'_>) -> Result<Vec<u8>> {
    let mut out = vec![0; q.operation().response_limit()];
    let n = wire::encode_response(&mut out, r, q, wire::Endpoint::Web)
        .map_err(|_| Error::InternalError)?;
    out.truncate(n);
    Ok(out)
}
impl Actions {
    pub fn with_budgets(store: &Store, budgets: crate::ceremony_budget::Budgets) -> Result<Self> {
        let origin = store
            .installation_origin()
            .map_err(store_error)?
            .ok_or(Error::Unavailable)?;
        let url = Url::parse(origin.as_str()).map_err(|_| Error::InternalError)?;
        let verifier = WebauthnBuilder::new(origin.rp_id(), &url)
            .map_err(|_| Error::InternalError)?
            .allow_subdomains(false)
            .allow_any_port(false)
            .timeout(CEREMONY)
            .build()
            .map_err(|_| Error::InternalError)?;
        Ok(Self {
            budgets,
            verifier: Arc::new(verifier),
            origin,
            generation: random()?,
            valid: true,
            pending: Vec::new(),
            workers: Arc::new(AtomicUsize::new(0)),
        })
    }
    pub fn invalidate(&mut self) {
        self.pending.clear();
        // No successful admission can cross invalidation, even if random generation fails.
        self.valid = false;
    }
    fn installation(&self, store: &Store) -> Result<()> {
        if !self.valid
            || store.installation_origin().map_err(store_error)?.as_ref() != Some(&self.origin)
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    fn reclaim(&mut self, now: Instant) {
        // Running jobs retain their reservation until completion, even after expiry.
        self.pending
            .retain(|p| p.state.is_none() || p.deadline > now);
    }
    /// Bind the user, current grant revision and trusted operation before issuing a challenge.
    pub fn begin(
        &mut self,
        bytes: &[u8],
        store: &Store,
        config: &wudo_core::config::Config,
        now: Instant,
    ) -> Result<Vec<u8>> {
        let q = wire::decode_request(bytes, wire::Endpoint::Web)?;
        let wire::Request::ActionBegin(v) = &q else {
            return Err(Error::UnsupportedOperation);
        };
        self.installation(store)?;
        self.reclaim(now);
        let user = store
            .user_by_name(v.user_name.0)
            .map_err(store_error)?
            .ok_or(Error::Unavailable)?
            .id;
        let revision = authorized_revision(store, user, v.action_id.0)?;
        let operation = config
            .actions()
            .iter()
            .find(|(id, _)| id.as_str() == v.action_id.0)
            .and_then(|(_, action)| crate::integrations::ConfiguredOperation::from_action(action))
            .ok_or(Error::Unavailable)?;
        let lease = self
            .budgets
            .ceremony(user)
            .map_err(|_| Error::Unavailable)?;
        let mut snapshots = Vec::new();
        let mut after = None;
        // Store bounds retained credentials globally to 1024 and active ones per user to 16.
        loop {
            let page = store
                .list_credentials(user, after.as_deref())
                .map_err(store_error)?
                .ok_or(Error::Unavailable)?;
            for c in page.items {
                if !c.revoked {
                    snapshots.push(
                        store
                            .authentication_snapshot(user, &c.id)
                            .map_err(store_error)?
                            .ok_or(Error::Unavailable)?,
                    );
                }
            }
            after = page.next_after;
            if after.is_none() {
                break;
            }
        }
        if snapshots.is_empty() || snapshots.len() > 16 {
            return Err(Error::Unavailable);
        }
        let keys: Vec<_> = snapshots.iter().map(|s| s.passkey().clone()).collect();
        let (options, state) = self
            .verifier
            .start_passkey_authentication(&keys)
            .map_err(|_| Error::InternalError)?;
        let p = &options.public_key;
        if p.extensions.is_some()
            || p.timeout != Some(120000)
            || options.mediation.is_some()
            || p.hints.is_some()
            || p.user_verification != webauthn_rs_proto::UserVerificationPolicy::Required
            || p.allow_credentials.iter().any(|c| c.type_ != "public-key")
        {
            return Err(Error::InternalError);
        }
        let id = wire::CeremonyId(random()?);
        if self.pending.iter().any(|p| p.id == id) {
            return Err(Error::InternalError);
        }
        let out = encode(
            &q,
            &wire::Response::ActionChallenge(wire::ActionChallenge {
                ceremony_id: id,
                remaining_ms: wire::Number(120000),
                options: wire::RequestOptions {
                    rp_id: wire::Text(&p.rp_id),
                    challenge: wire::Challenge(
                        p.challenge
                            .as_ref()
                            .try_into()
                            .map_err(|_| Error::InternalError)?,
                    ),
                    timeout_ms: wire::Number(120000),
                    allow_credentials: wire::CredentialList(
                        p.allow_credentials
                            .iter()
                            .map(|c| wire::Blob(c.id.as_ref()))
                            .collect(),
                    ),
                    user_verification: wire::Required::Required,
                },
            }),
        )?;
        self.pending.push(Pending {
            lease,
            id,
            user,
            action: v.action_id.0.to_owned(),
            revision,
            operation,
            deadline: now + CEREMONY,
            state: Some((state, snapshots)),
        });
        Ok(out)
    }
    /// Consume before verifier admission. Viewing/registration finish cannot use this state.
    pub fn take_finish(&mut self, bytes: &[u8], now: Instant) -> Result<Verification> {
        let wire::Request::ActionFinish(v) = wire::decode_request(bytes, wire::Endpoint::Web)?
        else {
            return Err(Error::UnsupportedOperation);
        };
        self.reclaim(now);
        let i = self
            .pending
            .iter()
            .position(|p| p.id == v.ceremony_id && p.state.is_some())
            .ok_or(Error::Unavailable)?;
        let mut pending = self.pending.remove(i);
        let (state, mut snapshots) = pending.state.take().ok_or(Error::Unavailable)?;
        if v.user_handle
            .is_some_and(|u| u.0 != *pending.user.as_bytes())
        {
            return Err(Error::VerificationFailed);
        }
        let j = snapshots
            .iter()
            .position(|s| s.passkey().cred_id().as_ref() == v.credential_id.0)
            .ok_or(Error::VerificationFailed)?;
        let snapshot = snapshots.swap_remove(j);
        self.workers
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 2).then_some(n + 1)
            })
            .map_err(|_| Error::Busy)?;
        let permit = Permit(self.workers.clone());
        let crypto = self.budgets.crypto(pending.user)?;
        let ceremony = pending.lease.clone();
        let response = PublicKeyCredential {
            id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.credential_id.0),
            raw_id: v.credential_id.0.to_vec().into(),
            type_: "public-key".into(),
            response: AuthenticatorAssertionResponseRaw {
                client_data_json: v.client_data.0.to_vec().into(),
                authenticator_data: v.authenticator_data.0.to_vec().into(),
                signature: v.signature.0.to_vec().into(),
                user_handle: v.user_handle.map(|u| u.0.to_vec().into()),
            },
            extensions: Default::default(),
        };
        self.pending.push(pending);
        Ok(Verification {
            _ceremony: ceremony,
            _crypto: crypto,
            id: v.ceremony_id,
            verifier: self.verifier.clone(),
            state,
            response,
            snapshot,
            _permit: permit,
        })
    }
    pub fn abort_verification(&mut self, id: wire::CeremonyId) {
        self.pending.retain(|p| p.id != id);
    }
    /// Persist verifier metadata before any privileged submission. This is not admission.
    pub fn complete(
        &mut self,
        verified: Verified,
        store: &mut Store,
        now: Instant,
    ) -> Result<Authenticated> {
        let i = self
            .pending
            .iter()
            .position(|p| p.id == verified.id && p.state.is_none())
            .ok_or(Error::Unavailable)?;
        let p = self.pending.remove(i);
        self.installation(store)?;
        if now >= p.deadline || authorized_revision(store, p.user, &p.action)? != p.revision {
            return Err(Error::Unavailable);
        }
        let result = verified.result?;
        let credential = verified.snapshot.passkey().cred_id().as_ref().to_vec();
        store
            .commit_authentication(verified.snapshot, &result)
            .map_err(store_error)?;
        Ok(Authenticated {
            pending: p,
            generation: self.generation,
            credential,
        })
    }
    /// Call only on the serialized owner, after canonical identity/state checks.
    /// The consumed result holds the target guard until submission finishes.
    pub fn admit(&mut self, ready: Ready, store: &Store, now: Instant) -> Result<Admitted> {
        self.validate_admission(&ready.auth, store, now)?;
        let auth = ready.auth;
        Ok(Admitted {
            prepared: ready.prepared,
            operation_id: wire::OperationId(random()?),
            _ceremony: auth.pending.lease,
        })
    }
    fn validate_admission(&self, auth: &Authenticated, store: &Store, now: Instant) -> Result<()> {
        self.installation(store)?;
        if auth.generation != self.generation
            || now >= auth.pending.deadline
            || authorized_revision(store, auth.pending.user, &auth.pending.action)?
                != auth.pending.revision
            || store
                .credential_for_authentication(auth.pending.user, &auth.credential)
                .map_err(store_error)?
                .is_none()
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
}
/// Internal, consuming capability. No client can construct or reuse it.
pub struct Authenticated {
    pending: Pending,
    generation: [u8; 32],
    credential: Vec<u8>,
}
pub struct Ready {
    auth: Authenticated,
    prepared: crate::integrations::Prepared,
}
pub struct Admitted {
    prepared: crate::integrations::Prepared,
    operation_id: wire::OperationId,
    _ceremony: crate::ceremony_budget::Lease,
}
impl Authenticated {
    /// Off-owner bounded backend work; the worker retains its slot through admission.
    pub fn prepare(self, backend: &crate::integrations::Integrations) -> Result<Ready> {
        if Instant::now() >= self.pending.deadline {
            return Err(Error::Unavailable);
        }
        let prepared = backend
            .prepare(self.pending.operation.clone())
            .map_err(|availability| {
                if availability == wire::Availability::Busy {
                    Error::Busy
                } else {
                    Error::Unavailable
                }
            })?;
        Ok(Ready {
            auth: self,
            prepared,
        })
    }
}
impl Admitted {
    /// One attempt only. Dropped replies, later revocations and resets do not retry it.
    pub fn submit(
        self,
        backend: &crate::integrations::Integrations,
        timeout: Duration,
    ) -> Result<wire::Admitted> {
        let state = match backend.submit(self.prepared, timeout) {
            crate::integrations::Submission::Accepted => wire::Accepted::Accepted,
            crate::integrations::Submission::Unknown => wire::Accepted::Unknown,
            crate::integrations::Submission::NotSubmitted => return Err(Error::Unavailable),
        };
        Ok(wire::Admitted {
            state,
            operation_id: self.operation_id,
        })
    }
}
fn authorized_revision(store: &Store, user: UserId, action: &str) -> Result<[u8; 32]> {
    // At most 128 configured actions; pages are bounded to 16. No unbounded scan.
    let mut after = None;
    loop {
        let page = store
            .list_grants(user, after.as_deref())
            .map_err(store_error)?
            .ok_or(Error::Unavailable)?;
        if let Some(item) = page.items.iter().find(|a| a.id == action) {
            return Ok(item.revision);
        }
        after = page.next_after;
        if after.is_none() {
            return Err(Error::Unavailable);
        }
    }
}
#[cfg(test)]
mod tests;
