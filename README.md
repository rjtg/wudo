# Wudo

**Wudo** means **Web User Do** and is pronounced "voodoo".

Wudo is a passkey-authenticated privilege broker for Linux. It lets users invoke administrator-defined privileged actions from a browser without exposing a remote shell or arbitrary command execution.

> Users choose what to do, never what to execute.

## Components

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
- **wudo-ui** — Rust/WASM browser UI served by `wudo-web`, with WebAuthn operations; PRF support is planned.
- **wudo-cli** — local bootstrap, recovery, configuration and administration.

## Initial reference use case

The planned reference use case is remotely starting an encrypted Paperless installation after reboot. The secret-handling and LUKS steps below are not implemented yet:

1. User selects `paperless.start`.
2. User authenticates with a passkey.
3. The browser uses WebAuthn PRF to unwrap a random Wudo-managed LUKS key.
4. The browser encrypts that key directly for `wudod`.
5. `wudo-web` only relays ciphertext.
6. `wudod` unlocks LUKS and runs the preconfigured start action.

The existing human LUKS passphrase remains as a recovery mechanism.

The daemon verifies actual WebAuthn responses rather than trusting web/UI claims. The planned secret path requires authenticated end-to-end encryption; that protocol is not implemented yet. Malicious UI delivery by a compromised web service is an accepted risk; UI attestation is out of scope. See `SECURITY.md`.

## Implementation status

Wudo is a development prototype for passkey-protected systemd start/stop actions.
It cannot yet unlock LUKS or run the complete encrypted Paperless workflow.

| Area | Status |
| --- | --- |
| Local initialization/reset, SQLite persistence and explicit upgrades | Implemented |
| Users, passkey enrollment, credential inspection and revocation | Implemented |
| Trusted action configuration and revision-bound user grants | Implemented |
| Browser sign-in, authorized action listing and status polling | Implemented; viewing sessions grant reads only |
| Fixed systemd start/stop and browser Run controls | Implemented; every invocation requires a fresh daemon-verified assertion |
| Real-systemd action E2E and Pi/physical-authenticator validation | Outstanding |
| PRF, secret wrappers, encrypted secret transport and provisioning | Not implemented; protocol/compatibility work remains |
| LUKS unlock and combined Paperless start | Not implemented |
| Audit and deployment/recovery tooling | Incomplete |

Native and WASM tests, linting and the UI build have passed for the action slice.
The enrollment browser test has passed previously, but the expanded viewing and
execution path still needs deployment validation. Synthetic backend tests do not
prove real-systemd behavior. See [action execution](docs/action-execution.md) for
implemented ordering, bounds, outcomes and remaining validation.

Current work and validation evidence live in [roadmap #20](https://github.com/rjtg/wudo/issues/20)
and [execution #24](https://github.com/rjtg/wudo/issues/24). Next is isolated
real-systemd/browser E2E, followed by target PRF compatibility and the reviewed
secret-handling/LUKS work. Issue counts are not a completion percentage: broader
milestones include unfinished scope even where individual slices are implemented.

The reviewed design and security baseline is in [SECURITY.md](SECURITY.md),
[architecture](docs/architecture.md), [domain model](docs/domain-model.md),
[secrets](docs/secrets.md) and [LUKS flow](docs/luks-flow.md). Unresolved secret
protocol and provisioning details are not finalized by the existing runtime.

## Development

The repository contains a Cargo workspace using stable Rust:

- `crates/wudo-core`: typed offline action/resource configuration and validation.
- `crates/wudod`: Unix IPC daemon, identity storage, WebAuthn verification and action admission/submission.
- `crates/wudo-web`: bounded enrollment/viewing/action relay and static UI service.
- `crates/wudo-cli`: local administration and offline validation, binary name `wudo`.
- `ui/wudo-ui`: Rust/WASM enrollment, sign-in, polling and action UI served by `wudo-web`.

The daemon uses Tokio, SQLite and the established webauthn-rs verifier. It
requires root for runtime use; ordinary Cargo tests use isolated temporary state.
The web service relays bounded requests over localhost HTTP behind a separate
HTTPS proxy and serves the Rust/WASM UI. Supported runtime actions are fixed
systemd start/stop without prerequisites or secrets. Secret transport and LUKS
remain unimplemented. See [browser enrollment](docs/browser-enrollment.md) for build,
proxy setup, enrollment and remaining real-device validation.

Root-managed action configuration and grants are described in the
[action/grant guide](docs/action-grants-proposal.md). This adds `wudo action list`,
`wudo grant USER ACTION`, `wudo revoke USER ACTION` and `wudo grant list USER`.
Installations with older identity schemas require `sudo wudo upgrade` for schema 4. Configuration
changes take effect at restart and invalidate grants for changed actions.

Local setup and enrollment commands are documented in
[installation setup](docs/installation-setup.md) and
[enrollment](docs/enrollment-implementation.md). `wudo init --reset` is explicitly
destructive to Wudo's identity state; normal init never overwrites it.

Inspect users and manage individual credentials through the root-only CLI:

```text
sudo wudo user list
sudo wudo credential list alice
sudo wudo credential show alice CREDENTIAL_ID
sudo wudo credential revoke alice CREDENTIAL_ID
```

Listings include users without passkeys and retained revoked credentials.
Pages contain at most 16 entries and print a continuation command when needed.
Revocation is permanent for the selected ID and does not rotate downstream
secrets. See [credential administration](docs/credential-administration-proposal.md).

Validate the example locally:

```text
cargo run -p wudo-cli -- config validate --file examples/paperless.v2.actions.toml
```

The schema-2 example includes planned LUKS actions, which remain unavailable at
runtime. Its standalone systemd stop action uses the implemented operation shape.
Validation checks structural validity only. It does not inspect devices, query systemd,
contact the daemon, provision secrets, or install configuration. See the
[configuration contract](docs/configuration-proposal.md) for limits and errors.

Run the same checks as CI from the repository root:

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

`rust-toolchain.toml` selects stable Rust with rustfmt and Clippy. Workspace
members forbid unsafe Rust. Commit `Cargo.lock` to keep dependency resolution
consistent. Parser and CLI tests cover malformed/oversized input, strict schema
and reference checks, safe diagnostics, and offline file handling.

Before adding secret handling, resolve the applicable protocol, PRF and
crash-safe provisioning decisions in the linked GitHub issues and reviewed
specifications. Existing action/authentication policies are documented in
[action execution](docs/action-execution.md).

## Task tracking

Use [GitHub Issues](https://github.com/rjtg/wudo/issues) for planned work and
progress. The [roadmap index (#20)](https://github.com/rjtg/wudo/issues/20) links
implementation work packages and the design decisions that gate them.

Read a task with `gh issue view <number> --repo rjtg/wudo --comments`.
Reviewed architecture/security decisions remain in the repository documents.

The [configuration contract](docs/configuration-proposal.md#action-schema-2-and-daemon-settings)
and [schema-2 example](examples/paperless.v2.actions.toml) describe current startup
configuration. The original schema-1 example remains a historical parser fixture;
nonempty schema-1 startup catalogs require explicit conversion.
