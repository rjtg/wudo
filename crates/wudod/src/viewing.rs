//! Read-only sign-in state owned by the daemon's serialized state worker.
//! This module cannot authorize or submit actions. Do not log handles or assertions.
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
    deadline: Instant,
    state: Option<(PasskeyAuthentication, Vec<AuthenticationSnapshot>)>,
}
struct Session {
    digest: [u8; 32],
    user: UserId,
    credential: Vec<u8>,
    deadline: Instant,
    last_poll: Option<Instant>,
}
pub struct Viewing {
    budgets: crate::ceremony_budget::Budgets,
    verifier: Arc<Webauthn>,
    origin: wire::InstallationOrigin,
    lifetime: Duration,
    pending: Vec<Pending>,
    sessions: Vec<Session>,
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
impl Viewing {
    pub fn new(store: &Store, lifetime_seconds: u64) -> Result<Self> {
        Self::with_budgets(
            store,
            lifetime_seconds,
            crate::ceremony_budget::Budgets::default(),
        )
    }
    pub fn with_budgets(
        store: &Store,
        lifetime_seconds: u64,
        budgets: crate::ceremony_budget::Budgets,
    ) -> Result<Self> {
        if !(60..=600).contains(&lifetime_seconds) {
            return Err(Error::InvalidRequest);
        }
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
            lifetime: Duration::from_secs(lifetime_seconds),
            pending: Vec::new(),
            sessions: Vec::new(),
            workers: Arc::new(AtomicUsize::new(0)),
        })
    }
    pub fn invalidate(&mut self) {
        self.pending.clear();
        self.sessions.clear();
    }
    fn installation(&self, store: &Store) -> Result<()> {
        if store.installation_origin().map_err(store_error)?.as_ref() != Some(&self.origin) {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    fn reclaim(&mut self, now: Instant) {
        // Running jobs retain their reservation until completion, even after expiry.
        self.pending
            .retain(|p| p.state.is_none() || p.deadline > now);
        self.sessions.retain(|s| s.deadline > now);
    }
    /// Share the same Budgets instance with enrollment and future action ceremonies.
    pub fn begin(&mut self, bytes: &[u8], store: &Store, now: Instant) -> Result<Vec<u8>> {
        let q = wire::decode_request(bytes, wire::Endpoint::Web)?;
        let wire::Request::ViewBegin(v) = &q else {
            return Err(Error::UnsupportedOperation);
        };
        self.installation(store)?;
        self.reclaim(now);
        let user = store
            .user_by_name(v.user_name.0)
            .map_err(store_error)?
            .ok_or(Error::Unavailable)?
            .id;
        if self.sessions.len() + self.pending.len() >= 128
            || self.sessions.iter().filter(|s| s.user == user).count()
                + self.pending.iter().filter(|p| p.user == user).count()
                >= 4
            || self.pending.len() >= 32
            || self.pending.iter().filter(|p| p.user == user).count() >= 2
        {
            return Err(Error::Unavailable);
        }
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
            deadline: now + CEREMONY,
            state: Some((state, snapshots)),
        });
        Ok(out)
    }
    /// Consume before verifier admission. Action/registration finish cannot use this state.
    pub fn take_finish(&mut self, bytes: &[u8], now: Instant) -> Result<Verification> {
        let wire::Request::ViewFinish(v) = wire::decode_request(bytes, wire::Endpoint::Web)? else {
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
    /// Serialize with all credential/root mutations. Persist before issuing a read token.
    pub fn complete(
        &mut self,
        verified: Verified,
        store: &mut Store,
        now: Instant,
    ) -> Result<wire::ViewSession> {
        let i = self
            .pending
            .iter()
            .position(|p| p.id == verified.id && p.state.is_none())
            .ok_or(Error::Unavailable)?;
        let p = self.pending.remove(i);
        self.installation(store)?;
        if now >= p.deadline {
            return Err(Error::Unavailable);
        }
        let result = verified.result?;
        let credential = verified.snapshot.passkey().cred_id().as_ref().to_vec();
        store
            .commit_authentication(verified.snapshot, &result)
            .map_err(store_error)?;
        let token = wire::ViewToken(random()?);
        let digest = openssl::sha::sha256(&token.0);
        if self.sessions.iter().any(|s| s.digest == digest) {
            return Err(Error::InternalError);
        }
        self.sessions.push(Session {
            digest,
            user: p.user,
            credential,
            deadline: now + self.lifetime,
            last_poll: None,
        });
        Ok(wire::ViewSession {
            token,
            remaining_ms: wire::Number(self.lifetime.as_millis() as u64),
        })
    }
    /// Synchronous initial projection: no backend calls and no execution authority.
    /// Until asynchronous observations are integrated all controls stay unavailable.
    pub fn actions(
        &mut self,
        bytes: &[u8],
        store: &Store,
        config: &wudo_core::config::Config,
        now: Instant,
    ) -> Result<Vec<u8>> {
        let q = wire::decode_request(bytes, wire::Endpoint::Web)?;
        let wire::Request::ViewActions(v) = &q else {
            return Err(Error::UnsupportedOperation);
        };
        self.installation(store)?;
        self.reclaim(now);
        let digest = openssl::sha::sha256(&v.token.0);
        let i = self
            .sessions
            .iter()
            .position(|s| openssl::memcmp::eq(&s.digest, &digest))
            .ok_or(Error::Unavailable)?;
        let s = &mut self.sessions[i];
        if store
            .credential_for_authentication(s.user, &s.credential)
            .map_err(store_error)?
            .is_none()
        {
            self.sessions.remove(i);
            return Err(Error::Unavailable);
        }
        if s.last_poll
            .is_some_and(|last| now.saturating_duration_since(last) < Duration::from_secs(2))
        {
            return Err(Error::Busy);
        }
        let remaining_ms = s.deadline.saturating_duration_since(now).as_millis() as u64;
        if remaining_ms == 0 {
            return Err(Error::Unavailable);
        }
        s.last_poll = Some(now);
        let page = store
            .list_grants(s.user, v.after.map(|a| a.0))
            .map_err(store_error)?
            .ok_or(Error::Unavailable)?;
        let mut rows = Vec::new();
        for item in &page.items {
            let action = config
                .actions()
                .iter()
                .find(|(id, _)| id.as_str() == item.id)
                .map(|(_, a)| a)
                .ok_or(Error::Unavailable)?;
            rows.push(wire::ViewAction {
                action_id: wire::Name(&item.id),
                description: wire::Text(&item.description),
                revision: wire::Blob(&item.revision),
                confirmation: action.confirmation,
                state: wire::UnitState::Unknown,
                availability: if crate::integrations::ConfiguredOperation::from_action(action)
                    .is_some()
                {
                    wire::Availability::StateUnavailable
                } else {
                    wire::Availability::Unsupported
                },
            });
        }
        encode(
            &q,
            &wire::Response::ViewPage(wire::ViewPage {
                remaining_ms: wire::Number(
                    s.deadline.saturating_duration_since(now).as_millis() as u64
                ),
                actions: wire::Items(rows),
                next_after: page.next_after.as_deref().map(wire::Name),
            }),
        )
    }
}

#[cfg(test)]
mod tests;
