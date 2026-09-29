# Wudo Roadmap

This is an initial work breakdown for Codex. Refine tasks before implementation when they touch unresolved security questions.

## Milestone 0 — Freeze the design baseline

No production implementation yet.

- Review `AGENTS.md`.
- Review threat model and component boundaries.
- Resolve or explicitly defer items in `docs/open-questions.md`.
- Define initial v1 scope.
- Decide repository/workspace layout.
- Define terminology and stable IDs.

Exit criterion: no implementation-critical security question is being guessed.

## Milestone 1 — Rust workspace and quality gates

- Create Cargo workspace.
- Add `wudo-core`, `wudod`, `wudo-web`, `wudo-cli` crates as appropriate.
- Establish formatting/clippy/test commands.
- Add CI.
- Add dependency policy/audit tooling if desired.
- No privileged functionality yet.

## Milestone 2 — Domain and configuration model

- Strong types for UserId, CredentialId, ActionId, SecretId.
- Strict action configuration parser.
- Secret definitions/state model.
- Authorization model.
- Config validation.
- Negative tests for unknown fields and invalid references.

## Milestone 3 — Local IPC

- Versioned typed protocol.
- Bounded framing.
- Unix-domain socket.
- Peer credential checks where available.
- Separate web-runtime and local-admin capabilities.
- Explicit error model.
- Fuzz/property tests where useful.

Do not add a generic execute-command IPC operation.

## Milestone 4 — Minimal privileged action agent

- Load trusted configuration.
- Direct process execution only.
- Fixed executable/argv.
- Timeout.
- bounded stdout/stderr.
- child cleanup.
- ownership/permission/symlink validation.
- audit events.

Test hostile IPC input extensively.

## Milestone 5 — Bootstrap, users and credentials

Requires WebAuthn protocol design.

- UNINITIALIZED state.
- local `wudo enroll` bootstrap initiation.
- short-lived enrollment binding/code.
- user model.
- multiple credentials per user.
- credential revocation.
- local root recovery.

## Milestone 6 — Web/UI authentication and action invocation

Requires resolution of agent-verifiable authorization.

- action listing;
- WebAuthn authentication;
- user authorization checks;
- explicit confirmation;
- short-lived action-bound authorization evidence;
- replay protection;
- action status/result UX.

## Milestone 7 — Audit and operations

- structured audit log;
- status/health;
- config validation command;
- safe diagnostic output;
- systemd units;
- Debian/Raspberry Pi deployment docs.

## Milestone 8 — Secret framework

Requires secret transport protocol to be resolved.

- Secret lifecycle.
- Credential wrappers.
- PRF capability handling.
- browser cryptographic handling.
- E2E browser -> wudod secret transport.
- zeroization/secret-safe errors.
- interrupted provisioning tests.

## Milestone 9 — LUKS backend

- Generate random K.
- Preserve existing recovery passphrase.
- Provision Wudo keyslot.
- safe `cryptsetup` input (never argv).
- unlock.
- add wrapper for another credential.
- revoke wrapper.
- rotate K safely.
- recovery tests.

## Milestone 10 — Paperless reference integration

- `paperless.start`.
- `paperless.stop`.
- verify expected mount source.
- start/stop Syncthing/Docker/Paperless safely.
- useful action progress/status.
- document installation on Raspberry Pi OS/Debian.

## Explicitly not initial scope

- arbitrary remote commands;
- remote shell;
- generic plugins;
- fleet management;
- OAuth/OIDC;
- Kubernetes;
- generic password manager;
- exposing plaintext downstream secrets through the API.
