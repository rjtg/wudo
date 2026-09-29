# AGENTS.md — Wudo

## Project

Wudo ("Web User Do", pronounced "voodoo") is a passkey-authenticated privilege broker for Linux.

Its purpose is to let authenticated users invoke a small set of administrator-defined privileged actions from a browser without exposing a remote shell or arbitrary command execution.

The central invariant is:

> Users choose what to do, never what to execute.

This is a security-sensitive Rust project. Prefer small, explicit, auditable designs over flexibility.

## Status

The repository is at the design/bootstrap stage. The documents under `docs/` are the current design baseline, but unresolved items are intentionally marked as such.

Do not silently resolve security-sensitive design questions while implementing. Document the decision or stop and ask for review.

## Components

The intended system has four user-facing/runtime components plus shared Rust code:

- `wudod`: privileged daemon, normally running as root.
- `wudo-web`: unprivileged HTTP/API service.
- `wudo-ui`: browser application.
- `wudo-cli`: local administrative CLI, typically invoked through `sudo`.
- shared core/protocol crates may be introduced where useful.

Trust boundaries matter more than crate boundaries.

### wudod

`wudod` is the security boundary.

It may:
- execute administrator-defined actions;
- manage privileged state;
- temporarily handle downstream plaintext secrets;
- interact with LUKS and other privileged operating-system facilities;
- expose a narrow local IPC interface.

It must:
- have no network listener;
- never parse HTTP;
- create WebAuthn challenges and verify registration/authentication responses using an established library;
- never invoke a shell;
- never accept an executable path, arbitrary argv, environment variables, or privileged filesystem paths from a remote client;
- validate every request independently;
- fail closed.

### wudo-web

`wudo-web` is unprivileged and network-facing.

Assume it can be fully compromised.

It may:
- serve/coordinate the API and UI;
- relay authenticated requests and opaque cryptographic messages;
- communicate with `wudod` through a Unix-domain socket.

A compromise of `wudo-web` must not automatically become arbitrary root command execution.

For downstream secrets, the design goal is stronger:

> In the intended protocol, `wudo-web` relays only ciphertext for downstream secrets such as a LUKS key.

An active compromise that replaces the served UI can steal browser-held secrets during use. This is an accepted risk; UI attestation is out of scope. See `SECURITY.md`.

### wudo-ui

`wudo-ui` is written in Rust, compiled to WebAssembly, and served by `wudo-web`. It runs in the user's browser with the browser bindings and generated JavaScript glue needed for WebAuthn.

It is responsible for user interaction, WebAuthn/passkey operations, and — where required — WebAuthn PRF based key derivation.

For the current threat model, the browser is allowed to hold a downstream secret such as a LUKS key briefly in memory. This is a deliberate tradeoff.

The UI must erase temporary secret material where practical and must never persist it.

### wudo-cli

`wudo-cli` is the local administrative interface.

It is used for operations requiring local administrator authority, including bootstrap, recovery, configuration management, and secret provisioning.

Do not assume `wudo-cli` and `wudo-web` have the same IPC permissions. Their allowed operations should be distinct and enforced by `wudod`.

## Non-negotiable security rules

1. Never execute `/bin/sh -c`, `bash -c`, `eval`, shell fragments, or equivalent.
2. Remote/user-controlled data must never become executable code.
3. A remote request must never supply:
   - executable path;
   - arbitrary command arguments;
   - environment variables;
   - arbitrary privileged paths.
4. Actions are referenced only by stable administrator-defined IDs.
5. `wudod` has no TCP/HTTP listener.
6. `wudo-web` never runs as root.
7. Configuration and privileged state must not be writable by the `wudo-web` account.
8. Unknown actions, fields, protocol versions, states, or policy values fail closed.
9. Bound all request sizes, output sizes, and execution times.
10. Never place secrets in logs, command-line arguments, panic messages, URLs, or error responses.
11. Prefer passing secrets through memory, pipes, or file descriptors.
12. Explicitly minimize the lifetime of plaintext secret buffers and zeroize where practical.
13. Check ownership, permissions, file type, and symlink behavior for privileged configuration and executable files.
14. Minimize dependencies in `wudod`.
15. Avoid `unsafe` Rust unless unavoidable and documented.
16. Add negative tests for every security boundary.
17. Do not add arbitrary-command or generic-plugin functionality.
18. A feature that weakens these invariants requires an explicit design/security review before implementation.

## Authorization model

Keep authentication, authorization, and cryptographic secret eligibility separate.

Conceptually:

```text
User ---- authorized for ----> Action ---- requires ----> Secret
  |
  +---- owns ----> Credential/Passkey ---- can unwrap ----> Secret
```

Authorization belongs primarily to the user:

> User X may invoke Action Y.

Cryptographic wrapping belongs to an individual credential:

> Credential C can derive the material needed to unwrap Secret S.

Do not model a passkey as the user itself. A user may have multiple credentials.

An action that requires a secret may exist before the secret has been provisioned. Such an action is not executable until its dependencies are ready.

## Action model

Actions are static administrator-defined capabilities.

Example:

```toml
[actions."paperless.start"]
description = "Unlock storage and start Paperless"
requires_secret = "paperless-luks"
confirmation = true

[actions."system.reboot"]
description = "Reboot this machine"
command = ["/usr/bin/systemctl", "reboot"]
confirmation = true
```

The exact configuration schema is not final. Preserve the invariant that clients select `paperless.start`, not `/usr/bin/...` plus arguments.

Prefer direct `execve`-style execution with a fixed executable and fixed arguments loaded from trusted configuration.

## Identity and bootstrap

Wudo must never implement "first browser becomes administrator."

Initial state:

```text
UNINITIALIZED
users = 0
```

Bootstrap is initiated locally, for example:

```text
sudo wudo enroll
```

The local operation creates a short-lived enrollment opportunity/code. The browser then creates a WebAuthn credential.

Store only public credential material and metadata. Never store the passkey private key or biometric information.

Root/local administration is the recovery authority. Loss of all passkeys must be recoverable through local root/console/SSH administration.

The identity model is:

```text
User
  -> zero or more Credentials
  -> zero or more Action authorizations
```

## Downstream secrets

A secret definition and secret material are separate concepts.

A configuration may define:

```text
Action paperless.start
  requires Secret paperless-luks

Secret paperless-luks
  state UNINITIALIZED
```

The secret can later transition to `READY` during an explicit privileged provisioning operation.

Expected lifecycle:

```text
define -> authorize -> provision -> use -> rotate/revoke
```

Provisioning is a privileged bootstrap step and may require both:
- local administrator authority;
- an enrolled, eligible passkey.

## LUKS reference design

The first reference integration is LUKS2.

Do not replace the user's existing recovery passphrase.

Desired layout:

```text
LUKS2
  slot A: existing human recovery passphrase
  slot B: random Wudo-managed key K
```

`K` is random high-entropy key material, not the user's passphrase and not raw WebAuthn PRF output.

For each eligible credential:

```text
PRF output
   -> KDF/HKDF
   -> KEK_credential

wrapper_credential = AEAD_Encrypt(KEK_credential, K)
```

Multiple credentials may therefore unwrap the same `K` without consuming multiple LUKS slots.

A credential revocation and a secret rotation are different operations:
- deleting a wrapper prevents future Wudo-mediated unwrap with that credential;
- it cannot revoke a copy of `K` that was already stolen;
- true cryptographic revocation requires rotating `K` and updating the downstream LUKS keyslot.

## Secret transport

Current design decision:

- The browser may briefly know plaintext `K`.
- `wudod` may briefly know plaintext `K`.
- `wudo-web` relays ciphertext and does not receive plaintext `K` in the intended protocol; malicious UI delivery remains an accepted risk.

During normal use:

1. Browser performs WebAuthn authentication/PRF.
2. Browser derives the credential KEK.
3. Browser obtains the stored wrapper and unwraps `K`.
4. Browser encrypts `K` directly for `wudod`.
5. `wudo-web` relays only ciphertext.
6. `wudod` decrypts `K`, supplies it to LUKS without argv exposure, and clears it.

The exact end-to-end encryption protocol between browser and `wudod` is NOT YET SPECIFIED. Do not invent custom cryptography. Select standard, reviewed primitives only after the protocol and threat model are documented.

## WebAuthn PRF

The LUKS design depends on the WebAuthn PRF extension.

Before treating this as production-ready:
- verify support with the actual target authenticator/browser combinations;
- define behavior when PRF is unsupported;
- document RP ID/origin requirements;
- document credential portability/synchronization implications.

Normal WebAuthn authentication alone does not provide an encryption key. Do not conflate signatures with PRF output.

## IPC and protocol

Prefer a small, versioned, typed protocol over the Unix-domain socket.

Requirements:
- explicit protocol version;
- strict schemas;
- bounded messages;
- reject unknown or invalid operations;
- peer identity/credentials checked where supported;
- separate administrative operations from web-runtime operations;
- no generic "execute command" request;
- no generic privileged filesystem primitive.

`wudod` creates WebAuthn challenges and verifies the actual responses. It trusts neither `wudo-web` nor UI claims of authentication, authorization, or confirmation. `wudo-web` is a transport relay, not an issuer of trusted authorization grants.

The daemon must bind each short-lived, single-use challenge to the intended operation, verify the assertion against enrolled public credential material and configured RP ID/origin, and independently enforce user authorization and credential status.

Exact ceremony/IPC schemas, expiry, replay consumption, enrollment binding, and secret-operation binding remain to be specified before implementation. Use an established WebAuthn verifier; do not implement cryptographic primitives. A valid assertion does not prove which action a potentially malicious UI displayed.

## Logging and audit

Security events should be auditable without logging secrets.

Candidate events:
- bootstrap/enrollment initiated/completed/failed;
- credential added/revoked;
- authorization granted/revoked;
- action requested/allowed/denied/completed/failed;
- secret provisioned/rotated/revoked;
- configuration validation failures.

Audit records should identify stable IDs and outcomes, not secret material.

## Coding expectations

- Rust stable unless a documented feature requires otherwise.
- Run `cargo fmt`.
- Run `cargo clippy --all-targets --all-features -- -D warnings` when feasible.
- Run all relevant tests.
- Prefer explicit types for security-sensitive identifiers and protocol messages.
- Keep privileged code small.
- Prefer boring code.
- Avoid clever abstractions that obscure data flow or trust boundaries.
- Treat parsing, deserialization, filesystem access, process execution, IPC, and cryptography as security-sensitive.
- Use established cryptographic libraries; never implement primitives.
- Make security-sensitive state transitions explicit.
- Ensure partial failures leave a recoverable/fail-closed state.

## Language server

Use the rust-analyzer LSP tools when navigating or modifying Rust code.

- Use LSP definitions/references instead of relying only on text search.
- Check LSP diagnostics after modifying Rust files.
- Resolve relevant diagnostics before considering a task complete.
- Still run cargo fmt, cargo clippy, and cargo test as required.

## Testing expectations

At minimum test:
- unknown action rejection;
- attempts to inject executable paths/argv;
- malformed and oversized IPC requests;
- unauthorized user/action combinations;
- replay/expired authorization data once that protocol exists;
- secret unavailable/uninitialized states;
- child timeout and output limits;
- symlink/ownership/permission failures;
- interrupted secret provisioning;
- credential revocation behavior;
- secret rotation behavior.

Integration tests should avoid requiring real production secrets.

## Agent workflow

For each task:

1. Read `AGENTS.md`, `SECURITY.md`, and the relevant `docs/`.
2. Identify affected trust boundaries.
3. State any unresolved design assumption before coding.
4. Add or update tests first where practical.
5. Implement the smallest change that satisfies the task.
6. Run formatting, linting, and tests.
7. Update documentation when behavior/protocol/state changes.
8. Do not expand scope opportunistically.

If the requested implementation conflicts with a security invariant, do not work around the invariant. Document the conflict and request a design decision.

## Task tracking

GitHub Issues in `rjtg/wudo` is the source of truth for task scope, dependencies,
acceptance criteria, and progress. Start from roadmap issue #20. Use the `gh`
CLI to read the issue and its comments before starting work, and inspect linked
prerequisites. For example:

```text
gh issue list --repo rjtg/wudo
gh issue view 20 --repo rjtg/wudo --comments
gh issue view <number> --repo rjtg/wudo --comments
```

Keep reviewed design specifications in `docs/` and security rules in
`SECURITY.md`/`AGENTS.md`; link them from issues. Local `tasks/` files are migration
pointers, not a second backlog. Do not treat issue proposals as approved
security decisions. When authorized to update issue progress, report actual
validation and remaining work; do not close an issue solely because an
unpublished local implementation exists.
