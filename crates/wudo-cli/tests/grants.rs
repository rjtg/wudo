use std::process::Command;
#[test]
fn invalid_grant_arguments_fail_before_ipc_without_echo() {
    for args in [
        vec!["action"],
        vec!["action", "list", "CANARY"],
        vec!["grant", "alice", "/CANARY"],
        vec!["revoke", "CANARY", "ok"],
        vec!["grant", "list", "alice", "--after", "CANARY"],
        vec!["grant", "alice", "ok", "extra"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_wudo"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&out.stderr).contains("CANARY"));
    }
}
