# Wudo

**Wudo** means **Web User Do** and is pronounced "voodoo".

Wudo is a passkey-authenticated privilege broker for Linux. It lets users invoke administrator-defined privileged actions from a browser without exposing a remote shell or arbitrary command execution.

> Users choose what to do, never what to execute.

## Planned components

```text
Browser
  |
  | HTTPS / WebAuthn
  v
wudo-ui
  |
  v
wudo-web                 unprivileged, network-facing
  |
  | Unix-domain socket
  v
wudod                    privileged security boundary
  |
  v
fixed administrator-defined actions

wudo-cli
  |
  | local administrative IPC
  v
wudod
```

- **wudod** — privileged daemon, WebAuthn challenge/verification authority, and authorization enforcement point.
- **wudo-web** — unprivileged web/API service; assume compromise.
- **wudo-ui** — Rust/WASM browser UI served by `wudo-web`, with WebAuthn and PRF operations.
- **wudo-cli** — local bootstrap, recovery, configuration and administration.

## Initial reference use case

The first concrete use case is remotely starting an encrypted Paperless installation after reboot:

1. User selects `paperless.start`.
2. User authenticates with a passkey.
3. The browser uses WebAuthn PRF to unwrap a random Wudo-managed LUKS key.
4. The browser encrypts that key directly for `wudod`.
5. `wudo-web` only relays ciphertext.
6. `wudod` unlocks LUKS and runs the preconfigured start action.

The existing human LUKS passphrase remains as a recovery mechanism.

The daemon verifies actual WebAuthn responses rather than trusting web/UI claims. Authenticated end-to-end encryption protects secret transport. Malicious UI delivery by a compromised web service is an accepted risk; UI attestation is out of scope. See `SECURITY.md`.

## Design status

This repository is intentionally design-first. See:

- `SECURITY.md`
- `docs/architecture.md`
- `docs/domain-model.md`
- `docs/secrets.md`
- `docs/luks-flow.md`
- `docs/open-questions.md`
- `tasks/000-roadmap.md`

Do not treat unresolved cryptographic or authorization protocol details as finalized.

## Development

The repository contains a minimal Cargo workspace using stable Rust:

- `crates/wudo-core`: reserved for shared domain/protocol types.
- `crates/wudod`: daemon scaffold.
- `crates/wudo-web`: web service scaffold.
- `crates/wudo-cli`: administrative CLI scaffold, with binary name `wudo`.
- `ui/wudo-ui`: reserved for the Rust/WASM frontend; not yet a Cargo crate.

There are no external crate dependencies. The binaries print an unimplemented
message and exit with failure. No root privileges are needed; no listeners,
IPC, process execution, authentication, or secret handling are implemented.

Run the same checks as CI from the repository root:

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

`rust-toolchain.toml` selects stable Rust with rustfmt and Clippy. Workspace
members forbid unsafe Rust. Commit `Cargo.lock` to keep dependency resolution
consistent. The scaffold has no behavioral tests yet; add relevant negative
tests as security boundaries are implemented.

Before implementing behavior, resolve the applicable items in
[open questions](docs/open-questions.md): configuration/state ownership, action
execution semantics, IPC/WebAuthn ceremonies, secret transport, and crash-safe
provisioning. None needs to be settled to build this scaffold.

## Task tracking

Use [GitHub Issues](https://github.com/rjtg/wudo/issues) for planned work and
progress. The [roadmap index (#20)](https://github.com/rjtg/wudo/issues/20) links
implementation work packages and the design decisions that gate them. The
recommended next design task is [configuration schema and validation (#15)](https://github.com/rjtg/wudo/issues/15).

Read a task with `gh issue view <number> --repo rjtg/wudo --comments`.
Reviewed architecture/security decisions remain in the repository documents.
