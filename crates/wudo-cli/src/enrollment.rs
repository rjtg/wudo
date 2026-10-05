use crate::admin;
use std::{ffi::OsString, process::ExitCode};
use wudo_protocol::v2::*;

pub(super) fn run(mut args: impl Iterator<Item = OsString>) -> ExitCode {
    let values: Vec<_> = args.by_ref().take(4).collect();
    if args.next().is_some() {
        return usage();
    }
    let Some(text) = values
        .iter()
        .map(|s| s.to_str())
        .collect::<Option<Vec<_>>>()
    else {
        return usage();
    };
    match execute(&text) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage) => usage(),
        Err(Failure::Protocol(e)) => {
            eprintln!("Enrollment request failed: {e:?}.");
            ExitCode::FAILURE
        }
        Err(Failure::Transport) => {
            eprintln!(
                "Enrollment request failed: connection-or-protocol-error; outcome may be unknown. Inspect the enrollment before retrying; closed handles may require local recovery."
            );
            ExitCode::FAILURE
        }
    }
}
enum Failure {
    Usage,
    Protocol(Error),
    Transport,
}
fn handle(value: &str) -> std::result::Result<[u8; 32], Failure> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Failure::Usage);
    }
    let mut id = [0; 32];
    for (n, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        id[n] = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Ok(id)
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}
fn exchange(request: &Request<'_>) -> std::result::Result<Vec<u8>, Failure> {
    encode_request(&mut [0; 4096], request, Endpoint::Admin).map_err(|_| Failure::Usage)?;
    let reply = admin::send(request).map_err(|_| Failure::Transport)?;
    match decode_response(&reply, request, Endpoint::Admin).map_err(|_| Failure::Transport)? {
        Response::Error(e) => Err(Failure::Protocol(e)),
        _ => Ok(reply),
    }
}
fn execute(args: &[&str]) -> std::result::Result<(), Failure> {
    let request = match args {
        ["inspect", id] => Request::EnrollmentInspect(EnrollmentRef {
            enrollment_id: EnrollmentId(handle(id)?),
        }),
        ["cancel", id] => Request::EnrollmentCancel(EnrollmentRef {
            enrollment_id: EnrollmentId(handle(id)?),
        }),
        ["approve", id, candidate] => {
            eprintln!(
                "Approval trusts this candidate for the selected user; it does not independently verify who owns the passkey."
            );
            Request::EnrollmentApprove(EnrollmentApprove {
                enrollment_id: EnrollmentId(handle(id)?),
                candidate_id: CandidateId(handle(candidate)?),
            })
        }
        [name] | [name, "--insecure"] => {
            let inspect = Request::UserInspect(UserInspect { name: Name(name) });
            let reply = exchange(&inspect)?;
            let Response::UserInfo(user) = decode_response(&reply, &inspect, Endpoint::Admin)
                .map_err(|_| Failure::Transport)?
            else {
                return Err(Failure::Transport);
            };
            let mode = if args.len() == 2 {
                eprintln!(
                    "Insecure enrollment: the first valid registration wins without local candidate approval and may gain this user's permissions. Grants and secret wrappers are not created."
                );
                Mode::Insecure
            } else {
                Mode::Confirm
            };
            Request::EnrollmentOpen(EnrollmentOpen {
                user_id: user.user_id,
                mode,
            })
        }
        _ => return Err(Failure::Usage),
    };
    let reply = exchange(&request)?;
    match decode_response(&reply, &request, Endpoint::Admin).map_err(|_| Failure::Transport)? {
        Response::Opened(v) => {
            println!(
                "Enrollment: {}\nExpires in: {} seconds",
                hex(&v.enrollment_id.0),
                v.remaining_ms.0 / 1000
            );
            if let Some(ticket) = v.ticket {
                println!(
                    "Ticket (transfer privately to the Wudo UI; never put it in a URL): {}",
                    hex(&ticket.0)
                );
            }
        }
        Response::OpenInspection(v) => println!(
            "User: {}\nMode: {:?}\nState: {:?}\nExpires in: {} seconds",
            admin::uuid(v.user_id),
            v.mode,
            v.state,
            v.remaining_ms.0 / 1000
        ),
        Response::CandidateInspection(v) => println!(
            "User: {}\nState: pending-approval\nCandidate: {}\nCredential fingerprint: {}\nExpires in: {} seconds\nThe fingerprint identifies a credential, not its human owner.",
            admin::uuid(v.user_id),
            hex(&v.candidate_id.0),
            hex(&v.fingerprint.0),
            v.remaining_ms.0 / 1000
        ),
        Response::Cancelled(_) => println!("Enrollment cancelled."),
        Response::Activated(v) => println!("Credential activated: {}", hex(v.credential_id.0)),
        _ => return Err(Failure::Transport),
    }
    Ok(())
}
fn usage() -> ExitCode {
    eprintln!(
        "Usage: wudo enroll USER [--insecure] | wudo enroll inspect ENROLLMENT_ID | wudo enroll approve ENROLLMENT_ID CANDIDATE_ID | wudo enroll cancel ENROLLMENT_ID"
    );
    ExitCode::from(2)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handles_and_invalid_commands_do_not_connect_or_echo_values() {
        assert!(handle(&"ab".repeat(32)).is_ok());
        for value in [
            "short".into(),
            "AB".repeat(32),
            "0".repeat(65),
            "z".repeat(64),
        ] {
            assert!(handle(&value).is_err());
        }
        for args in [
            vec![],
            vec!["inspect", "CANARY"],
            vec!["alice", "--unsafe"],
            vec!["approve", "CANARY", "CANARY"],
            vec!["UPPERCASE"],
        ] {
            assert!(matches!(execute(&args), Err(Failure::Usage)));
        }
    }
}
