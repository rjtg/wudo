# Task 001 — Review and scaffold only

## Goal

Turn the current design documents into a minimal repository skeleton without implementing security-sensitive behavior.

## Instructions

1. Read all repository Markdown documents.
2. Summarize any contradictions or implementation-blocking ambiguities.
3. Propose a Cargo workspace layout for:
   - shared domain/protocol types;
   - `wudod`;
   - `wudo-web`;
   - `wudo-cli`.
4. Propose where `wudo-ui` should live, but do not select a heavy frontend framework without justification.
5. Create only:
   - workspace manifests;
   - empty/minimal crates;
   - formatting/lint/test configuration;
   - CI for fmt/clippy/test;
   - basic README pointers.
6. Do **not** implement:
   - process execution;
   - WebAuthn;
   - cryptography;
   - secret storage;
   - root operations;
   - IPC authorization.

## Acceptance criteria

- `cargo fmt --check` passes.
- `cargo clippy --all-targets --all-features -- -D warnings` passes.
- `cargo test --all` passes.
- No crate needs root.
- No network listener or process execution exists.
- Any proposed deviation from the documented architecture is explained before implementation.
