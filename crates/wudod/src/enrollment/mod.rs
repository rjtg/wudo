//! Bounded enrollment state for a single serialized daemon owner.
//!
//! The storage worker owns this state and serializes completion/approval with
//! durable mutation. Verifier settings come from the installation store;
//! `Verification::run` executes off the I/O thread. No Debug implementations expose
//! tickets, challenges or verifier records. All wire input is decoded here.
mod adapter;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use webauthn_rs::prelude::*;
use wudo_protocol::v2::{self as wire, Error, Result};
use wudo_store::Store;

const WINDOW: Duration = Duration::from_secs(600);
const CEREMONY: Duration = Duration::from_secs(120);
struct Opportunity {
    id: wire::EnrollmentId,
    user: wudo_store::UserId,
    mode: wire::Mode,
    ticket_hash: Option<[u8; 32]>,
    deadline: Instant,
    stage: Stage,
}
enum Stage {
    Open,
    Pending {
        lease: crate::ceremony_budget::Lease,
        id: wire::CeremonyId,
        deadline: Instant,
        state: PasskeyRegistration,
    },
    Verifying {
        id: wire::CeremonyId,
        deadline: Instant,
    },
    Candidate {
        id: wire::CandidateId,
        key: Passkey,
    },
}
/// In-memory opportunities disappear on restart. Use one instance per daemon.
pub struct Enrollment {
    budgets: crate::ceremony_budget::Budgets,
    origin: wire::InstallationOrigin,
    verifier: Arc<Webauthn>,
    opportunities: Vec<Opportunity>,
    workers: Arc<AtomicUsize>,
}
struct Permit(Arc<AtomicUsize>);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
/// Single-use owned job. Dropping it releases worker capacity; call completion
/// with its result after running. A dropped job leaves its opportunity busy
/// until opportunity expiry or cancellation, never active.
pub struct Verification {
    _ceremony: crate::ceremony_budget::Lease,
    _crypto: crate::ceremony_budget::Lease,
    verifier: Arc<Webauthn>,
    enrollment: wire::EnrollmentId,
    ceremony: wire::CeremonyId,
    state: PasskeyRegistration,
    response: RegisterPublicKeyCredential,
    _permit: Permit,
}
pub struct Verified {
    _ceremony: crate::ceremony_budget::Lease,
    _crypto: crate::ceremony_budget::Lease,
    enrollment: wire::EnrollmentId,
    ceremony: wire::CeremonyId,
    result: Result<Passkey>,
    _permit: Permit,
}
impl Verification {
    /// Performs established-library verification; never logs library errors.
    pub fn run(self) -> Verified {
        let result = self
            .verifier
            .finish_passkey_registration(&self.response, &self.state)
            .map_err(|_| Error::VerificationFailed)
            .and_then(|key| {
                if key.cred_id().as_ref() == self.response.raw_id.as_ref() {
                    Ok(key)
                } else {
                    Err(Error::VerificationFailed)
                }
            });
        Verified {
            _ceremony: self._ceremony,
            _crypto: self._crypto,
            enrollment: self.enrollment,
            ceremony: self.ceremony,
            result,
            _permit: self._permit,
        }
    }
}
fn random() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::InternalError)?;
    Ok(bytes)
}
fn remaining(deadline: Instant, now: Instant) -> Result<u64> {
    let ms = deadline.saturating_duration_since(now).as_millis() as u64;
    if ms == 0 {
        Err(Error::Unavailable)
    } else {
        Ok(ms)
    }
}
fn store_error(e: wudo_store::Error) -> Error {
    match e {
        wudo_store::Error::Conflict => Error::Conflict,
        wudo_store::Error::Capacity | wudo_store::Error::InvalidInput => Error::Unavailable,
        _ => Error::InternalError,
    }
}
fn encoded(
    request: &wire::Request<'_>,
    endpoint: wire::Endpoint,
    response: &wire::Response<'_>,
) -> Result<Vec<u8>> {
    let mut out = vec![0; request.operation().response_limit()];
    let n = wire::encode_response(&mut out, response, request, endpoint)
        .map_err(|_| Error::InternalError)?;
    out.truncate(n);
    Ok(out)
}
impl Enrollment {
    /// Construct solely from durable root-configured installation settings.
    pub fn new(store: &Store) -> Result<Self> {
        Self::with_budgets(store, crate::ceremony_budget::Budgets::default())
    }
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
            origin,
            verifier: Arc::new(verifier),
            opportunities: Vec::new(),
            workers: Arc::new(AtomicUsize::new(0)),
        })
    }
    /// Clear every transient handle before a reset attempt, including on failure.
    pub fn invalidate(&mut self) {
        self.opportunities.clear();
    }
    /// Keep the shared crypto capacity across resets while replacing verifier settings.
    pub fn reload(&mut self, store: &Store) -> Result<()> {
        self.invalidate();
        let replacement = Self::new(store)?;
        self.origin = replacement.origin;
        self.verifier = replacement.verifier;
        Ok(())
    }
    /// Infrastructure failure after take still consumes the challenge, but allows
    /// a fresh begin inside the unchanged live opportunity.
    pub fn abort_verification(&mut self, id: wire::CeremonyId) {
        for o in &mut self.opportunities {
            if matches!(o.stage, Stage::Verifying{id: current,..} if current==id) {
                o.stage = Stage::Open;
            }
        }
    }
    fn check_installation(&self, store: &Store) -> Result<()> {
        if store.installation_origin().map_err(store_error)?.as_ref() != Some(&self.origin) {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    fn reclaim(&mut self, now: Instant) {
        self.opportunities
            .retain(|o| remaining(o.deadline, now).is_ok());
        for o in &mut self.opportunities {
            if matches!(&o.stage, Stage::Pending{deadline,..} if remaining(*deadline,now).is_err())
            {
                o.stage = Stage::Open;
            }
        }
    }
    /// Handle fully bounded admin/begin messages. Finish must use `take_finish`
    /// so crypto work can run independently while cancellation remains available.
    pub fn request(
        &mut self,
        bytes: &[u8],
        endpoint: wire::Endpoint,
        store: &mut Store,
        now: Instant,
    ) -> Result<Vec<u8>> {
        let request = wire::decode_request(bytes, endpoint)?;
        self.check_installation(store)?;
        self.reclaim(now);
        match &request {
            wire::Request::EnrollmentOpen(v) => {
                let user = wudo_store::UserId::from_bytes(v.user_id.0)
                    .map_err(|_| Error::InvalidRequest)?;
                store.enrollment_credentials(user).map_err(store_error)?;
                if store.remaining_credential_capacity().map_err(store_error)?
                    <= self.opportunities.len()
                {
                    return Err(Error::Unavailable);
                }

                if self.opportunities.len() >= 4
                    || self.opportunities.iter().any(|o| {
                        o.user == user
                            || (o.mode == wire::Mode::Insecure && v.mode == wire::Mode::Insecure)
                    })
                {
                    return Err(Error::Busy);
                }
                let id = wire::EnrollmentId(random()?);
                if self.opportunities.iter().any(|o| o.id == id) {
                    return Err(Error::InternalError);
                }
                let ticket = if v.mode == wire::Mode::Confirm {
                    Some(wire::Ticket(random()?))
                } else {
                    None
                };
                let reply = encoded(
                    &request,
                    endpoint,
                    &wire::Response::Opened(wire::Opened {
                        enrollment_id: id,
                        remaining_ms: wire::Number(600000),
                        ticket,
                    }),
                )?;
                self.opportunities.push(Opportunity {
                    id,
                    user,
                    mode: v.mode,
                    ticket_hash: ticket.map(|t| openssl::sha::sha256(&t.0)),
                    deadline: now + WINDOW,
                    stage: Stage::Open,
                });
                Ok(reply)
            }
            wire::Request::EnrollmentCancel(v) => {
                let i = self
                    .opportunities
                    .iter()
                    .position(|o| o.id == v.enrollment_id)
                    .ok_or(Error::Unavailable)?;
                self.opportunities.remove(i);
                encoded(
                    &request,
                    endpoint,
                    &wire::Response::Cancelled(wire::CancelledResult {
                        state: wire::Cancelled::Cancelled,
                    }),
                )
            }
            wire::Request::EnrollmentInspect(v) => {
                let o = self
                    .opportunities
                    .iter()
                    .find(|o| o.id == v.enrollment_id)
                    .ok_or(Error::Unavailable)?;
                let ms = wire::Number(remaining(o.deadline, now)?);
                let response = match &o.stage {
                    Stage::Candidate { id, key } => {
                        wire::Response::CandidateInspection(wire::CandidateInspection {
                            state: wire::PendingApproval::PendingApproval,
                            user_id: wire::UserId(*o.user.as_bytes()),
                            mode: o.mode,
                            remaining_ms: ms,
                            candidate_id: *id,
                            credential_id: wire::Blob(key.cred_id().as_ref()),
                            fingerprint: wire::Fingerprint(openssl::sha::sha256(
                                key.cred_id().as_ref(),
                            )),
                        })
                    }
                    stage => wire::Response::OpenInspection(wire::OpenInspection {
                        state: if matches!(stage, Stage::Open) {
                            wire::OpenState::Open
                        } else {
                            wire::OpenState::Registering
                        },
                        user_id: wire::UserId(*o.user.as_bytes()),
                        mode: o.mode,
                        remaining_ms: ms,
                    }),
                };
                encoded(&request, endpoint, &response)
            }
            wire::Request::EnrollmentApprove(v) => {
                let i = self
                    .opportunities
                    .iter()
                    .position(|o| o.id == v.enrollment_id)
                    .ok_or(Error::Unavailable)?;
                let o = &self.opportunities[i];
                let Stage::Candidate { id, key } = &o.stage else {
                    return Err(Error::Unavailable);
                };
                if o.mode != wire::Mode::Confirm || *id != v.candidate_id {
                    return Err(Error::Unavailable);
                }
                let reply = encoded(
                    &request,
                    endpoint,
                    &wire::Response::Activated(wire::Activated {
                        state: wire::Active::Active,
                        credential_id: wire::Blob(key.cred_id().as_ref()),
                    }),
                )?;
                // Removing before the transaction prevents retries after uncertain writes.
                let o = self.opportunities.remove(i);
                let Stage::Candidate { key, .. } = o.stage else {
                    unreachable!()
                };
                store
                    .activate_credential(o.user, &key)
                    .map_err(store_error)?;
                Ok(reply)
            }
            wire::Request::RegistrationBegin(_) | wire::Request::RegistrationBeginInsecure => {
                let digest = match &request {
                    wire::Request::RegistrationBegin(v) => Some(openssl::sha::sha256(&v.ticket.0)),
                    _ => None,
                };
                let o = self
                    .opportunities
                    .iter_mut()
                    .find(|o| match (o.ticket_hash.as_ref(), digest.as_ref()) {
                        (Some(a), Some(b)) => openssl::memcmp::eq(a, b),
                        (None, None) => o.mode == wire::Mode::Insecure,
                        _ => false,
                    })
                    .ok_or(Error::Unavailable)?;
                if !matches!(o.stage, Stage::Open) {
                    return Err(Error::Busy);
                }
                let lease = self.budgets.ceremony(o.user)?;
                let ids = store.enrollment_credentials(o.user).map_err(store_error)?;
                let user = store
                    .user_by_id(o.user)
                    .map_err(store_error)?
                    .ok_or(Error::Unavailable)?;
                let (options, state) = self
                    .verifier
                    .start_passkey_registration(
                        Uuid::from_bytes(*o.user.as_bytes()),
                        &user.name,
                        &user.label,
                        Some(ids.into_iter().map(Into::into).collect()),
                    )
                    .map_err(|_| Error::InternalError)?;
                let deadline = (now + CEREMONY).min(o.deadline);
                let ms = remaining(deadline, now)?;
                let id = wire::CeremonyId(random()?);
                let options = adapter::options(&options, ms)?;
                let reply = encoded(
                    &request,
                    endpoint,
                    &wire::Response::RegistrationChallenge(wire::RegistrationChallenge {
                        ceremony_id: id,
                        remaining_ms: wire::Number(ms),
                        options,
                    }),
                )?;
                o.stage = Stage::Pending {
                    lease,
                    id,
                    deadline,
                    state,
                };
                Ok(reply)
            }
            _ => Err(Error::UnsupportedOperation),
        }
    }
    /// Atomically consumes a structurally valid finish before worker admission.
    pub fn take_finish(
        &mut self,
        bytes: &[u8],
        endpoint: wire::Endpoint,
        now: Instant,
    ) -> Result<Verification> {
        let wire::Request::RegistrationFinish(v) = wire::decode_request(bytes, endpoint)? else {
            return Err(Error::UnsupportedOperation);
        };
        self.reclaim(now);
        let o = self
            .opportunities
            .iter_mut()
            .find(|o| matches!(&o.stage,Stage::Pending{id,..} if *id == v.ceremony_id))
            .ok_or(Error::Unavailable)?;
        let Stage::Pending {
            lease,
            id,
            deadline,
            state,
        } = std::mem::replace(&mut o.stage, Stage::Open)
        else {
            unreachable!()
        };
        self.workers
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 2).then_some(n + 1)
            })
            .map_err(|_| Error::Busy)?;
        let permit = Permit(self.workers.clone());
        let crypto = self.budgets.crypto(o.user)?;
        let response = adapter::response(&v)?;
        o.stage = Stage::Verifying { id, deadline };
        Ok(Verification {
            _ceremony: lease,
            _crypto: crypto,
            verifier: self.verifier.clone(),
            enrollment: o.id,
            ceremony: id,
            state,
            response,
            _permit: permit,
        })
    }
    /// Rechecks cancellation/expiry before candidate creation or durable activation.
    /// The caller serializes this method and root approval with all store writes.
    pub fn complete(
        &mut self,
        verified: Verified,
        store: &mut Store,
        now: Instant,
    ) -> Result<wire::RegistrationState> {
        self.check_installation(store)?;
        self.reclaim(now);
        let i = self
            .opportunities
            .iter()
            .position(|o| {
                o.id == verified.enrollment
                    && matches!(&o.stage,Stage::Verifying{id,..} if *id == verified.ceremony)
            })
            .ok_or(Error::Unavailable)?;
        let Stage::Verifying { deadline, .. } = self.opportunities[i].stage else {
            unreachable!()
        };
        self.opportunities[i].stage = Stage::Open;
        remaining(deadline, now)?;
        let key = verified.result?;
        if store
            .credential_id_exists(key.cred_id().as_ref())
            .map_err(store_error)?
        {
            return Err(Error::Unavailable);
        }
        // A pending candidate reserves capacity through the one-opportunity/user
        // rule. Other durable writers still must recheck at activation.
        store
            .enrollment_credentials(self.opportunities[i].user)
            .map_err(store_error)?;
        if self.opportunities[i].mode == wire::Mode::Confirm {
            self.opportunities[i].stage = Stage::Candidate {
                id: wire::CandidateId(random()?),
                key,
            };
            Ok(wire::RegistrationState::PendingApproval)
        } else {
            let o = self.opportunities.remove(i);
            store
                .activate_credential(o.user, &key)
                .map_err(|e| match store_error(e) {
                    Error::Conflict => Error::Unavailable,
                    other => other,
                })?;
            Ok(wire::RegistrationState::Active)
        }
    }
}

#[cfg(test)]
mod tests;
