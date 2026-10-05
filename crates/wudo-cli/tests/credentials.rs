use std::process::{Command, Stdio};
#[test]
fn invalid_administrative_inputs_fail_before_ipc_without_echoing_values() {
    for args in [
        vec!["credential"],
        vec!["credential", "list"],
        vec!["credential", "list", "CANARY"],
        vec!["credential", "list", "alice", "--after", "CANARY"],
        vec!["credential", "show", "alice", "0"],
        vec!["credential", "show", "alice", "AA"],
        vec!["credential", "revoke", "alice", "CANARY"],
        vec!["credential", "revoke", "alice", "00", "extra"],
        vec!["user", "list", "--after", "CANARY"],
        vec!["user", "list", "extra"],
    ] {
        let r = Command::new(env!("CARGO_BIN_EXE_wudo"))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(r.status.code(), Some(2));
        assert!(r.stdout.is_empty());
        let error = String::from_utf8(r.stderr).unwrap();
        assert!(!error.contains("CANARY"));
        assert!(!error.contains("connection-or-protocol-error"));
    }
}
