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

Creates WebAuthn challenges and verifies registration/authentication responses using an established library. Checks authorization independently; web/UI claims are untrusted. Detailed ceremony and replay rules remain to be specified.

No HTTP parsing or network listener.

#### Runtime decision

Use Tokio for `wudod`, initially with a current-thread async runtime and only
required features enabled. It coordinates Unix IPC, deadlines, process I/O and
shutdown. This decision does not add HTTP or a web framework to the daemon.

Keep parsing, policy and state-transition logic synchronous where practical.
Bound admitted connections, tasks, queues and blocking work explicitly. Blocking
work must not run on the async thread; a current-thread runtime can still use
separate blocking threads, which require their own limits.

The daemon owns operation lifetimes independently of client connections.
Dropping a future or timing out a request does not undo an unlock, stop an
already-running blocking call, or necessarily cancel a systemd job. Execution
and cleanup semantics must be specified before privileged operations are added.

Rationale: the planned combination of IPC, process monitoring and deadlines
benefits from one established I/O runtime rather than custom thread/polling
coordination. The cost is extra dependencies and explicit async cancellation
reasoning. A synchronous bounded-worker design was considered; it remains
simpler for a strictly serial service but fits the planned monitoring work less
well. The web/UI framework suggestions are not finalized by this decision.

IPC uses CBOR only, framed by a four-byte big-endian payload length, with an
explicit protocol version in the payload. No encoding negotiation, JSON fallback
or compression. Logs contain bounded event metadata rather than payload dumps.
The implemented status-only slice and its reviewed decoder/access policy are
described in the [IPC specification](ipc-proposal.md).

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

The UI is written in Rust and compiled to WebAssembly, with browser bindings and generated JavaScript glue as needed. `wudo-web` serves it. The initial enrollment form uses wasm-bindgen/web-sys directly; a future action
dashboard framework remains undecided. See [browser enrollment](browser-enrollment.md)
for the Axum relay, bounded HTTP transport and selected HTTPS proxy deployment.

Malicious UI delivery by a compromised `wudo-web` is an accepted risk, including theft of browser-held secrets and misleading action displays. UI attestation is out of scope. Authenticated encryption still keeps plaintext secrets out of intended relay messages.

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
