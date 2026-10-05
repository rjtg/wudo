use std::process::{Command, Stdio};
#[test]
fn noninteractive_init_requires_a_valid_explicit_origin() {
    for args in [
        vec!["init"],
        vec!["init", "--reset", "--origin", "https://pi.lan"],
        vec!["init", "--reset", "--yes"],
        vec!["init", "--yes", "--origin", "https://pi.lan"],
        vec!["init", "--reset", "--reset"],
        vec![
            "init",
            "--reset",
            "--yes",
            "--origin",
            "http://CANARY.invalid",
        ],
        vec!["init", "--origin"],
        vec!["init", "--origin", "http://CANARY.invalid"],
        vec![
            "init",
            "--origin",
            "https://pi.lan",
            "--origin",
            "https://other.lan",
        ],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_wudo"))
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2));
        let error = String::from_utf8(result.stderr).unwrap();
        assert!(!error.contains("CANARY"));
        assert!(!error.contains("connection-or-protocol-error"));
        if args.len() == 1 {
            assert!(error.contains("--origin is required"));
        }
    }
}
