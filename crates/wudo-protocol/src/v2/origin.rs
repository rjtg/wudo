//! Installation origin validation shared by the CLI and privileged store.
use super::{Error, Result};

pub const MAX_ORIGIN: usize = 270;
#[derive(Clone, PartialEq, Eq)]
pub struct InstallationOrigin {
    origin: String,
    rp_id: String,
}
impl InstallationOrigin {
    /// Accept canonical lowercase ASCII DNS names and an optional decimal port.
    /// A root slash and explicit default port are normalized away. No IP literals,
    /// credentials, percent escapes, IDNA conversion or general URL paths.
    pub fn parse(input: &str) -> Result<Self> {
        if input.len() > MAX_ORIGIN {
            return Err(Error::InvalidRequest);
        }
        let authority = input
            .strip_prefix("https://")
            .ok_or(Error::InvalidRequest)?;
        let authority = authority.strip_suffix('/').unwrap_or(authority);
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => {
                let n: u16 = port.parse().map_err(|_| Error::InvalidRequest)?;
                if n == 0 || n.to_string() != port {
                    return Err(Error::InvalidRequest);
                }
                (host, Some(n))
            }
            None => (authority, None),
        };
        if host.is_empty()
            || host.len() > 253
            || !host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
        {
            return Err(Error::InvalidRequest);
        }
        let url = url::Url::parse(input).map_err(|_| Error::InvalidRequest)?;
        if !matches!(url.host(), Some(url::Host::Domain(h)) if h==host) {
            return Err(Error::InvalidRequest);
        }
        let origin = match port {
            Some(n) if n != 443 => format!("https://{host}:{n}"),
            _ => format!("https://{host}"),
        };
        Ok(Self {
            origin,
            rp_id: host.into(),
        })
    }
    pub fn as_str(&self) -> &str {
        &self.origin
    }
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }
}
