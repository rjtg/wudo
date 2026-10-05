use crate::admin;
use std::{ffi::OsString, process::ExitCode};
use wudo_protocol::v2::*;

enum Failure {
    Usage,
    Protocol(Error),
    Transport,
}
fn outcome(result: std::result::Result<(), Failure>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage) => {
            eprintln!(
                "Usage: wudo user list [--after NAME] | wudo credential list USER [--after ID] | wudo credential show USER ID | wudo credential revoke USER ID"
            );
            ExitCode::from(2)
        }
        Err(Failure::Protocol(e)) => {
            eprintln!("Administrative request failed: {e:?}.");
            ExitCode::FAILURE
        }
        Err(Failure::Transport) => {
            eprintln!(
                "Administrative request failed: connection-or-protocol-error; write outcome may be unknown. Use credential show to inspect before retrying."
            );
            ExitCode::FAILURE
        }
    }
}
fn send(q: &Request<'_>) -> std::result::Result<Vec<u8>, Failure> {
    encode_request(&mut [0; 4096], q, Endpoint::Admin).map_err(|_| Failure::Usage)?;
    let bytes = admin::send(q).map_err(|_| Failure::Transport)?;
    match decode_response(&bytes, q, Endpoint::Admin).map_err(|_| Failure::Transport)? {
        Response::Error(e) => Err(Failure::Protocol(e)),
        _ => Ok(bytes),
    }
}
pub(super) fn list_users(after: Option<&str>) -> ExitCode {
    outcome((|| {
        let q = Request::UserList(UserList {
            after: after.map(Name),
        });
        let bytes = send(&q)?;
        let Response::UserPage(p) =
            decode_response(&bytes, &q, Endpoint::Admin).map_err(|_| Failure::Transport)?
        else {
            return Err(Failure::Transport);
        };
        print!("{}", users_output(&p));
        Ok(())
    })())
}
fn users_output(p: &UserPage<'_>) -> String {
    let mut out = String::new();
    if p.users.0.is_empty() {
        out.push_str("No users on this page.\n");
    }
    for u in &p.users.0 {
        out.push_str(&format!(
            "{}\t{}\t{:?}\n",
            u.name.0,
            admin::uuid(u.user_id),
            u.label.0
        ));
    }
    if let Some(next) = p.next_after {
        out.push_str(&format!("Next: sudo wudo user list --after {}\n", next.0));
    }
    out
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn id(s: &str) -> std::result::Result<Vec<u8>, Failure> {
    if !(2..=2046).contains(&s.len())
        || !s.len().is_multiple_of(2)
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Failure::Usage);
    }
    let digit = |b: u8| {
        if b.is_ascii_digit() {
            b - b'0'
        } else {
            b - b'a' + 10
        }
    };
    Ok(s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| digit(p[0]) * 16 + digit(p[1]))
        .collect())
}
pub(super) fn run(mut args: impl Iterator<Item = OsString>) -> ExitCode {
    let values: Vec<_> = args.by_ref().take(4).collect();
    if args.next().is_some() {
        return outcome(Err(Failure::Usage));
    }
    let Some(text) = values
        .iter()
        .map(|v| v.to_str())
        .collect::<Option<Vec<_>>>()
    else {
        return outcome(Err(Failure::Usage));
    };
    outcome(execute(&text))
}
fn execute(args: &[&str]) -> std::result::Result<(), Failure> {
    let (name, target) = match args {
        ["list", name] => (*name, None),
        ["list", name, "--after", cursor] => (*name, Some(id(cursor)?)),
        ["show" | "revoke", name, target] => (*name, Some(id(target)?)),
        _ => return Err(Failure::Usage),
    };
    let inspect = Request::UserInspect(UserInspect { name: Name(name) });
    let bytes = send(&inspect)?;
    let Response::UserInfo(u) =
        decode_response(&bytes, &inspect, Endpoint::Admin).map_err(|_| Failure::Transport)?
    else {
        return Err(Failure::Transport);
    };
    if u.name.0 != name {
        return Err(Failure::Transport);
    }
    let q = match args[0] {
        "list" => Request::CredentialList(CredentialQuery {
            user_id: u.user_id,
            after: target.as_deref().map(Blob),
        }),
        "show" => Request::CredentialInspect(CredentialRef {
            user_id: u.user_id,
            credential_id: Blob(target.as_deref().ok_or(Failure::Usage)?),
        }),
        "revoke" => Request::CredentialRevoke(CredentialRef {
            user_id: u.user_id,
            credential_id: Blob(target.as_deref().ok_or(Failure::Usage)?),
        }),
        _ => return Err(Failure::Usage),
    };
    let bytes = send(&q)?;
    let p = decode_response(&bytes, &q, Endpoint::Admin).map_err(|_| Failure::Transport)?;
    println!("User: {} ({})", name, admin::uuid(u.user_id));
    match p {
        Response::CredentialPage(p) => {
            if p.credentials.0.is_empty() {
                println!("No credentials on this page.");
            }
            for c in p.credentials.0 {
                println!("{}\t{}", hex(c.credential_id.0), state(c.state));
            }
            if let Some(next) = p.next_after {
                println!(
                    "Next: sudo wudo credential list {name} --after {}",
                    hex(next.0)
                );
            }
        }
        Response::CredentialInfo(c) => {
            println!(
                "Credential: {}\nState: {}\nFingerprint (SHA-256 of ID): {}",
                hex(c.credential_id.0),
                state(c.state),
                hex(&c.fingerprint.0)
            );
        }
        Response::CredentialRevoked(c) => {
            println!(
                "Credential: {}\nState: revoked\nRevocation does not rotate downstream secrets.",
                hex(c.credential_id.0)
            );
        }
        _ => return Err(Failure::Transport),
    }
    Ok(())
}
fn state(s: CredentialState) -> &'static str {
    match s {
        CredentialState::Active => "active",
        CredentialState::Revoked => "revoked",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn user_labels_are_escaped_and_ids_are_full_length() {
        let mut id_bytes = [0; 16];
        id_bytes[6] = 0x40;
        id_bytes[8] = 0x80;
        let p = UserPage {
            users: Items(vec![UserInfo {
                user_id: UserId(id_bytes),
                name: Name("alice"),
                label: Label("Alice\"\\\u{202e}"),
            }]),
            next_after: None,
        };
        let text = users_output(&p);
        assert!(text.contains("alice"));
        assert!(text.contains("\\\""));
        assert!(!text.contains('\u{202e}'));
        let raw = vec![0xab; 1023];
        assert!(id(&hex(&raw)).unwrap_or_default() == raw);
        assert!(id(&"ab".repeat(1024)).is_err());
        assert!(id("").is_err());
    }
}
