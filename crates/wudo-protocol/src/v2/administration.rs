//! Contextual validation of administrative responses.
use super::*;

pub(super) fn response<'a>(body: &'a [u8], request: &Request<'_>) -> Result<Response<'a>> {
    match request {
        Request::UserList(q) => {
            let p = UserPage::read(body)?;
            let mut previous = q.after.map(|n| n.0).unwrap_or("");
            for (i, u) in p.users.0.iter().enumerate() {
                if u.name.0 <= previous || p.users.0[..i].iter().any(|v| v.user_id == u.user_id) {
                    return Err(Error::InvalidRequest);
                }
                previous = u.name.0;
            }
            if let Some(next) = p.next_after
                && (p.users.0.len() != 16 || next.0 != previous)
            {
                return Err(Error::InvalidRequest);
            }
            Ok(Response::UserPage(p))
        }
        Request::CredentialList(q) => {
            let p = CredentialPage::read(body)?;
            if p.user_id != q.user_id {
                return Err(Error::InvalidRequest);
            }
            let mut previous = q.after.map(|v| v.0).unwrap_or(&[]);
            for c in &p.credentials.0 {
                if c.credential_id.0 <= previous {
                    return Err(Error::InvalidRequest);
                }
                previous = c.credential_id.0;
            }
            if let Some(next) = p.next_after
                && (p.credentials.0.len() != 16 || next.0 != previous)
            {
                return Err(Error::InvalidRequest);
            }
            Ok(Response::CredentialPage(p))
        }
        Request::CredentialInspect(q) => {
            let p = CredentialInfo::read(body)?;
            if p.user_id != q.user_id || p.credential_id != q.credential_id {
                return Err(Error::InvalidRequest);
            }
            Ok(Response::CredentialInfo(p))
        }
        Request::CredentialRevoke(q) => {
            let p = CredentialRevoked::read(body)?;
            if p.user_id != q.user_id || p.credential_id != q.credential_id {
                return Err(Error::InvalidRequest);
            }
            Ok(Response::CredentialRevoked(p))
        }
        _ => Err(Error::InvalidRequest),
    }
}
