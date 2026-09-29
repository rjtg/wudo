# Architecture

## Components

### `wudod`

Root daemon and final enforcement point.

Responsibilities:
- load/validate trusted configuration;
- maintain privileged state;
- enforce operation type and state;
- execute fixed actions without a shell;
- manage/provision downstream secrets;
- perform privileged LUKS operations;
- expose narrow local IPC.

No HTTP and no WebAuthn parsing.

### `wudo-web`

Unprivileged network service.

Responsibilities:
- HTTP/API transport;
- serve or coordinate `wudo-ui`;
- relay WebAuthn-related data;
- relay opaque encrypted secret messages;
- communicate with `wudod`.

Assume full compromise.

### `wudo-ui`

Browser application.

Responsibilities:
- display available operations/status;
- WebAuthn registration/authentication UX;
- explicit confirmation for sensitive actions;
- WebAuthn PRF operations;
- unwrap downstream secret `K` when needed;
- encrypt `K` end-to-end for `wudod`;
- never persist plaintext secrets.

### `wudo-cli`

Local administration.

Responsibilities may include:
- bootstrap;
- enrollment/recovery initiation;
- action/secret configuration;
- user and authorization management;
- secret provisioning/rotation;
- health/config validation;
- audit inspection.

Administrative IPC must be distinguishable from web-runtime IPC.

## Logical data flow

```text
                         local admin
                             |
                         wudo-cli
                             |
                             v
Browser -> wudo-ui -> wudo-web -> [Unix socket] -> wudod -> privileged action
  |                                             |
  +-------------- WebAuthn/passkey              +-> LUKS / systemd / fixed exec
```

## Suggested repository shape

This is guidance, not a fixed requirement:

```text
wudo/
├── AGENTS.md
├── README.md
├── SECURITY.md
├── docs/
├── tasks/
├── crates/
│   ├── wudo-core/
│   ├── wudod/
│   ├── wudo-web/
│   └── wudo-cli/
└── ui/
    └── wudo-ui/
```

A Rust-based UI is not required. Choose the smallest maintainable browser stack once UI requirements are clearer.

## Deployment target

Initial target:
- Linux;
- systemd;
- Debian/Raspberry Pi OS class systems;
- local Unix-domain IPC;
- HTTPS supplied directly or through a clearly documented deployment arrangement.

The first real integration target is a Raspberry Pi running encrypted Paperless storage.

## Design principle

The privileged side should remain useful and understandable even if every network-facing component is hostile.
