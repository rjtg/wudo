# Local user administration

Status: **approved, including explicit upgrade; implemented locally**.
Tracks #3/#15 and roadmap #20. Builds on the committed
[SQLite store](identity-persistence-proposal.md).

## Commands and wire contract

All commands below use the existing root-only admin socket. The CLI checks the
daemon's kernel UID before sending a request. No command accepts a database path.

| CLI | v2 operation | Request body | Successful response body |
| --- | --- | --- | --- |
| `sudo wudo upgrade` | `store.upgrade` (new) | `{}` | `{state:"ready"}` |
| `sudo wudo init [--origin HTTPS_ORIGIN]` | `installation.initialize` | `{origin: text}` | `{state:"ready"}` |
| `sudo wudo user create NAME --label LABEL` | `user.create` (existing) | `{name:Name,label:Label}` | `{user_id:UserId}` (existing) |
| `sudo wudo user show NAME` | `user.inspect` (new) | `{name:Name}` | `{user_id:UserId,name:Name,label:Label}` |

Use existing typed name/label/UUID limits and strict CBOR v2 envelopes. The administrative
operations in the table above have 4096-byte request/response caps. The web endpoint denies all
these administrative operations before dispatch. Enrollment and explicit installation reset are now available as described in
[enrollment](enrollment-implementation.md) and [setup](installation-setup.md).
User listing and credential inspection/revocation are now available under the
[credential administration contract](credential-administration-proposal.md),
including bounded list-response exceptions. Targeted user mutation and grants
remain later work.

Creation prints the UUID; inspection prints the UUID, name and label with
unambiguous escaping for terminal output. Neither says the user is enrolled or
authorized. Exit codes: 0 success, 1 operation/transport failure, 2 usage.
Errors remain category-only; never echo rejected argument values or SQL errors.

Initializing an already configured store returns `conflict`, never an overwrite.
An upgraded, unconfigured store without credentials can be configured while
preserving users; historical unbound credentials prevent configuration. A missing user returns
`unavailable`. Duplicate names return `conflict`; exhausted user capacity or an
uninitialized/unhealthy store returns `unavailable`; a full worker queue returns
`busy`. Malformed schemas return `invalid-request`. Internal storage failures
return `internal-error` and make identity operations unavailable until restart.

Keep v1 status behavior unchanged. v2 status also only reports IPC readiness;
it does not imply initialized identity storage or WebAuthn readiness. Enrollment/registration operations are also enabled under their reviewed
contract; action operations remain unsupported. Use the accepted bounded v2
transport/version dispatch policy; never downgrade a mutating request to v1.

## Installation and startup

Use fixed `/var/lib/wudo/identity.sqlite3`. The administrator or service setup
creates `/var/lib/wudo` as root:root, mode 0700, without access/default ACLs.
The daemon does not recursively create or repair directories. Validate `/`,
`/var`, `/var/lib` and `/var/lib/wudo` through directory descriptors without
following symlinks. Ancestors must be root-owned and not group/other writable;
reject ACLs that violate the existing strict directory policy. Check the final
directory's exact owner/mode/ACL policy and keep its descriptor for the lifetime
of the worker and hold an exclusive nonblocking lock on that directory inode.
SQLite NOFOLLOW rejects procfs descriptor aliases. Consequently SQLite uses the
fixed `/var/lib/wudo` path after descriptor validation; compare its device/inode
with the retained descriptor before each job. Root is trusted not to replace
ancestors during a call. No path is supplied by IPC. This is deliberately not a
custom SQLite VFS.

Missing database in that valid directory means UNINITIALIZED: status and explicit
initialization are available, create/inspect fail closed. Existing valid state
means READY. A recognized supported older layout is maintenance-only: status
and explicit upgrade remain available, while user operations are unavailable.
Existing invalid, incompatible, unsafe or partial state causes
startup failure; it never becomes UNINITIALIZED. Directory validation failure
also prevents startup. Initialization failure moves the live store to FAILED,
requiring local inspection and restart, without automatic file removal.

This changes deployment prerequisites: the privileged smoke harness must provide
an isolated `/var/lib/wudo` as well as `/run/wudo`, without changing host state.
Root remains trusted; protection against root replacing files is out of scope.

## Explicit migrations

`wudo init` creates the current schema using embedded migrations.
`wudo upgrade` validates existing state and invokes `rusqlite_migration`; it
never initializes missing state, downgrades, resets, or loads SQL from disk.
On a current database it succeeds without schema changes. Startup never runs
migrations. Migration failure leaves the worker unavailable until restart.

Schema v3 adds singleton installation settings. Validated v1/v2 stores require
explicit upgrade and retain their users/credentials. Installation setup is
separate from upgrade; see [installation setup](installation-setup.md). Both historical and current layouts have exact
validators. Version 0, unknown newer versions and forged version/schema
combinations are rejected. A synthetic failed migration tests rollback.
Released migrations are append-only and embedded in the binary. Tests must
check old records and final schemas, not just the version counter.

## Worker, timeouts and shutdown

One dedicated thread owns the connection and enrollment state; no SQLite call runs on the Tokio
event-loop thread. Use a bounded queue of four commands plus one executing
command, with nonblocking admission for general administration. Enrollment requests await
queue capacity within socket admission/deadline bounds. Two bounded verification
jobs return completion to this owner; see the enrollment contract. Queue entries own bounded validated input
and their response channel; no SQL or client filesystem paths enter the queue.

Attach the existing five-second exchange deadline. Before starting a queued
command, skip it if its deadline passed or its receiver was dropped. Once a
transaction starts, client disconnection or timeout does not cancel it.
Because IPC uses a write-half-close, a full peer disconnect may not be detected
until replying; disconnection alone is not a promise to cancel queued work. SQLite
may commit even when the reply is lost. The CLI must report an uncertain outcome
on transport failure, never automatically retry a write; use `user show NAME`
to inspect the result. Repeating initialization never deletes existing state.

On shutdown, stop admission, discard queued commands, let the current transaction
finish and close the connection. Do not abort a thread mid-transaction. SQLite's
100 ms lock wait bounds lock contention, not arbitrary kernel I/O stalls; do not
promise the status-only shutdown latency for a blocked storage syscall. Tests
must show that storage work does not block status or signal handling. Service
manager forced termination remains possible, with SQLite recovery on restart.

## Acceptance tests and remaining boundaries

- End-to-end initialize/create/show, unchanged v1 status, v2 status and restart.
- Root-only dispatch; web requests cannot initialize, create or inspect users.
- Missing state versus corrupt/partial state; no implicit creation or reset.
- Symlinked ancestors/leaves, wrong owner/mode/ACL, hard links and unsafe sidecars.
- Queue saturation, expired queued writes and disconnect before execution.
- Disconnect during commit, duplicate retry and inspection of durable result.
- Worker failure, poisoned store, shutdown with queued/in-flight work.
- CLI argument limits, safe output and verification of the daemon's kernel UID.
- Isolated privileged deployment smoke test supplied separately for maintainer use.

Enrollment verification, installation RP/origin binding,
grants, future schema transformations and backup recovery remain separate slices. Creating a user
does not establish any of them.

## Deployment and verification

In addition to the existing `/run/wudo` setup, create `/var/lib/wudo` as root:root
with mode 0700 and no access/default ACLs. The daemon refuses missing or unsafe
state directories. Then run the daemon with its existing web UID/GID arguments:

```text
sudo wudo init --origin https://wudo.home.example
sudo wudo user create alice --label Alice
sudo wudo user show alice
sudo wudo upgrade
```

`wudo status` retains the v1 wire contract. Structurally malformed envelopes now
close without a reply under the v2 dispatch policy; recognized v1 requests and
errors keep their original encoding and 4096-byte bound. Admission allows at
most 64 KiB before version dispatch, as approved in the v2 contract.

The smoke harness now isolates both `/run` and `/var/lib`, checks initialization,
creation, upgrade and inspection across restart in addition to peer permissions
and signals. It must be run explicitly on a suitable host; unprivileged test
success does not establish production ownership or power-loss behavior.

## Accepted initialization refinement

The maintainer moved installation address setup into `wudo init`: an explicit
`--origin` parameter, or a prompt when omitted in an interactive terminal.
The installation supports one origin, with RP ID derived from its hostname.
Required future installation settings follow the same parameter/prompt pattern.
Implemented locally; see [installation setup](installation-setup.md) for validation,
legacy protocol compatibility, and upgrade/setup behavior.
