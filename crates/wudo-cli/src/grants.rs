use crate::admin;
use std::{ffi::OsString, process::ExitCode};
use wudo_protocol::v2::*;
fn send(q: &Request<'_>) -> std::result::Result<Vec<u8>, ()> {
    let bytes = admin::send(q)?;
    if matches!(
        decode_response(&bytes, q, Endpoint::Admin),
        Ok(Response::Error(_)) | Err(_)
    ) {
        return Err(());
    }
    Ok(bytes)
}
pub(super) fn run(command: &str, mut args: impl Iterator<Item = OsString>) -> ExitCode {
    let values: Vec<_> = args.by_ref().take(5).collect();
    let Some(text) = values
        .iter()
        .map(|v| v.to_str())
        .collect::<Option<Vec<_>>>()
    else {
        return usage();
    };
    if args.next().is_some() {
        return usage();
    }
    let (user, action, after) = match (command, text.as_slice()) {
        ("action", ["list"]) => (None, None, None),
        ("action", ["list", "--after", after]) => (None, None, Some(*after)),
        ("grant", ["list", user]) => (Some(*user), None, None),
        ("grant", ["list", user, "--after", after]) => (Some(*user), None, Some(*after)),
        ("grant" | "revoke", [user, action]) => (Some(*user), Some(*action), None),
        _ => return usage(),
    };
    // Validate every argument before IPC, including values used only in the
    // second request after name lookup. Never echo invalid command arguments.
    let mut id = [0; 16];
    id[6] = 0x40;
    id[8] = 0x80;
    let make = |id| match (user, action) {
        (None, _) => Request::ActionList(ActionList {
            after: after.map(Name),
        }),
        (Some(_), None) => Request::GrantList(GrantQuery {
            user_id: id,
            after: after.map(Name),
        }),
        (_, Some(action)) => {
            let q = GrantRef {
                user_id: id,
                action_id: Name(action),
            };
            if command == "grant" {
                Request::GrantCreate(q)
            } else {
                Request::GrantRevoke(q)
            }
        }
    };
    if encode_request(&mut [0; 4096], &make(UserId(id)), Endpoint::Admin).is_err()
        || user.is_some_and(|name| {
            encode_request(
                &mut [0; 4096],
                &Request::UserInspect(UserInspect { name: Name(name) }),
                Endpoint::Admin,
            )
            .is_err()
        })
    {
        return usage();
    }
    let result = (|| {
        let id = if let Some(name) = user {
            let q = Request::UserInspect(UserInspect { name: Name(name) });
            let bytes = send(&q)?;
            let Response::UserInfo(u) =
                decode_response(&bytes, &q, Endpoint::Admin).map_err(|_| ())?
            else {
                return Err(());
            };
            if u.name.0 != name {
                return Err(());
            }
            u.user_id
        } else {
            UserId(id)
        };
        let q = make(id);
        let bytes = send(&q)?;
        match decode_response(&bytes, &q, Endpoint::Admin).map_err(|_| ())? {
            Response::ActionPage(p) => print_page(p.actions, p.next_after, None),
            Response::GrantPage(p) => print_page(p.actions, p.next_after, user),
            Response::GrantChanged(p) => println!(
                "Action: {}\nRevision: {}\nGranted: {}",
                p.action_id.0,
                hex(p.revision.0),
                p.granted
            ),
            _ => return Err(()),
        }
        Ok(())
    })();
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        eprintln!("Action/grant administration failed; inspect current grants before retrying.");
        ExitCode::FAILURE
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
fn print_page(items: Items<ActionEntry<'_>>, next: Option<Name<'_>>, user: Option<&str>) {
    if items.0.is_empty() {
        println!("No actions on this page.");
    }
    for a in items.0 {
        println!(
            "{}\t{}\t{:?}",
            a.action_id.0,
            hex(a.revision.0),
            a.description.0
        );
    }
    if let Some(next) = next {
        if let Some(user) = user {
            println!("Next: sudo wudo grant list {user} --after {}", next.0);
        } else {
            println!("Next: sudo wudo action list --after {}", next.0);
        }
    }
}
fn usage() -> ExitCode {
    eprintln!(
        "Usage: wudo action list [--after ID] | wudo grant USER ACTION | wudo revoke USER ACTION | wudo grant list USER [--after ID]"
    );
    ExitCode::from(2)
}
