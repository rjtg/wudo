//! Administrative projections encoded while the state owner holds their data.
use super::{Error, Reply, Store, map_error, wire as v};

pub(super) fn request(store: &mut Store, bytes: &[u8]) -> Result<Reply, Error> {
    let q = v::decode_request(bytes, v::Endpoint::Admin)?;
    let user = |id: v::UserId| wudo_store::UserId::from_bytes(id.0).map_err(map_error);
    let state = |revoked| {
        if revoked {
            v::CredentialState::Revoked
        } else {
            v::CredentialState::Active
        }
    };
    let encode = |response: v::Response<'_>| {
        let mut out = vec![0; q.operation().response_limit()];
        let n = v::encode_response(&mut out, &response, &q, v::Endpoint::Admin)
            .map_err(|_| Error::InternalError)?;
        out.truncate(n);
        Ok(Reply::Encoded(out))
    };
    match &q {
        v::Request::ActionList(query) => {
            let p = store
                .list_actions(query.after.map(|v| v.0))
                .map_err(map_error)?;
            encode(v::Response::ActionPage(v::ActionPage {
                actions: v::Items(action_entries(&p.items)),
                next_after: p.next_after.as_deref().map(v::Name),
            }))
        }
        v::Request::GrantList(query) => {
            let p = store
                .list_grants(user(query.user_id)?, query.after.map(|v| v.0))
                .map_err(map_error)?
                .ok_or(Error::Unavailable)?;
            encode(v::Response::GrantPage(v::GrantPage {
                user_id: query.user_id,
                actions: v::Items(action_entries(&p.items)),
                next_after: p.next_after.as_deref().map(v::Name),
            }))
        }
        v::Request::GrantCreate(query) | v::Request::GrantRevoke(query) => {
            let granted = matches!(q, v::Request::GrantCreate(_));
            let revision = store
                .set_grant(user(query.user_id)?, query.action_id.0, granted)
                .map_err(map_error)?
                .ok_or(Error::Unavailable)?;
            encode(v::Response::GrantChanged(v::GrantChanged {
                user_id: query.user_id,
                action_id: query.action_id,
                revision: v::Blob(&revision),
                granted,
            }))
        }

        v::Request::UserList(q) => {
            let p = store.list_users(q.after.map(|n| n.0)).map_err(map_error)?;
            encode(v::Response::UserPage(v::UserPage {
                users: v::Items(
                    p.items
                        .iter()
                        .map(|u| v::UserInfo {
                            user_id: v::UserId(*u.id.as_bytes()),
                            name: v::Name(&u.name),
                            label: v::Label(&u.label),
                        })
                        .collect(),
                ),
                next_after: p.next_after.as_deref().map(v::Name),
            }))
        }
        v::Request::CredentialList(q) => {
            let p = store
                .list_credentials(user(q.user_id)?, q.after.map(|v| v.0))
                .map_err(map_error)?
                .ok_or(Error::Unavailable)?;
            encode(v::Response::CredentialPage(v::CredentialPage {
                user_id: q.user_id,
                credentials: v::Items(
                    p.items
                        .iter()
                        .map(|c| v::CredentialEntry {
                            credential_id: v::Blob(&c.id),
                            state: state(c.revoked),
                        })
                        .collect(),
                ),
                next_after: p.next_after.as_deref().map(v::Blob),
            }))
        }
        v::Request::CredentialInspect(q) => {
            let c = store
                .inspect_credential(user(q.user_id)?, q.credential_id.0)
                .map_err(map_error)?
                .ok_or(Error::Unavailable)?;
            encode(v::Response::CredentialInfo(v::CredentialInfo {
                user_id: q.user_id,
                credential_id: v::Blob(&c.id),
                state: state(c.revoked),
                fingerprint: v::Fingerprint(openssl::sha::sha256(&c.id)),
            }))
        }
        v::Request::CredentialRevoke(q) => {
            let c = store
                .revoke_owned_credential(user(q.user_id)?, q.credential_id.0)
                .map_err(map_error)?
                .ok_or(Error::Unavailable)?;
            encode(v::Response::CredentialRevoked(v::CredentialRevoked {
                user_id: q.user_id,
                credential_id: v::Blob(&c.id),
                state: v::Revoked::Revoked,
            }))
        }
        _ => Err(Error::UnsupportedOperation),
    }
}

fn action_entries(items: &[wudo_store::ActionSummary]) -> Vec<v::ActionEntry<'_>> {
    items
        .iter()
        .map(|a| v::ActionEntry {
            action_id: v::Name(&a.id),
            description: v::Text(&a.description),
            revision: v::Blob(&a.revision),
        })
        .collect()
}
