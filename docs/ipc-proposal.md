# Minimal Unix IPC specification

Status: **approved; status-only implementation published and CI verified**.
Tracking: [#4](https://github.com/rjtg/wudo/issues/4).
The endpoint policy, schema, limits, dependencies and lifecycle below were
explicitly approved before implementation. The historical filename is retained.

The accepted [v2 WebAuthn message contract](webauthn-wire-proposal.md) specifies future
extensions. It does not change the implemented v1 contract documented here.

## First slice

Implement only `wudo status` and a daemon `status` response. The response proves
that the expected daemon answered protocol v1; it does not report action,
storage, authentication, provisioning or application readiness. Do not load
privileged action configuration merely to serve this response.

Use a dedicated `wudo-protocol` crate for typed messages and framing. Keep its
dependencies limited to serialization needs; do not couple IPC to the TOML
parser in `wudo-core`, HTTP libraries or browser types. The daemon and CLI use
this crate. Select `minicbor` with default features disabled, using its
slice-based `Decoder` and fixed-buffer `Encoder` directly. Decode into small
Rust enums/structs through explicit field matching, not a generic map or derive
behavior that may skip unknown fields. CBOR primitives remain library code.
Cargo.lock records the resolved versions (initially minicbor 2.3.0, Tokio 1.53.1
and rustix 1.1.5).

Rationale: `minicbor` provides non-allocating decoding, borrowed strings, map
lengths and the current byte position. These let this flat protocol enforce
its complete schema without recursion or a generic object tree. Ciborium was
considered: its Serde support and recursion limits are useful, but controlling
this deliberately restricted CBOR profile through direct decoder calls is
clearer for this small schema. Neither choice alone enforces Wudo's policy.

References: [minicbor Decoder](https://docs.rs/minicbor/latest/minicbor/decode/struct.Decoder.html),
[Ciborium decoding](https://docs.rs/ciborium/latest/ciborium/de/index.html).
Review the selected version's source and verify all claims with negative tests
before adding it to the daemon's dependency graph.

## Endpoints and permissions

Production endpoints:

- `/run/wudo/admin.sock`: root-owned, mode `0600`.
- `/run/wudo/web.sock`: root-owned, designated web-service group, mode `0660`.
- `/run/wudo`: root-owned, mode `0755`, no untrusted write access or ACL grants.

The sockets are separate capability namespaces, not interchangeable aliases.
The first CLI command uses only the admin endpoint. The web endpoint is tested
with a local protocol client until `wudo-web` exists.

| Request | Admin socket, root peer | Web socket, configured web UID | Any other peer |
| --- | --- | --- | --- |
| `status` | Allow | Allow, same minimal response | Reject before reading payload |
| Enrollment/grant/configuration mutation | Not implemented | Not implemented | Reject |
| Action invocation or secret delivery | Not implemented | Not implemented | Reject |
| Unknown operation or protocol version | Reject | Reject | Reject |

Check kernel-provided Unix peer credentials on every accepted connection. UID
0 is required on admin; exact configured nonzero UID is required on web. Group
membership and socket access alone do not authorize requests. Root does not
implicitly select the admin namespace by connecting to the web socket. Peer
identity describes a process credential, not proof that a particular executable
is running. Local root remains the trusted recovery authority.

The CLI must also verify that the server peer UID is 0 before trusting its
response. No user/role/UID field in the wire message can establish peer identity.
A root process deliberately passing an already-authorized socket to another
process is outside this peer-credential guarantee; no descriptor passing is
part of Wudo's protocol.

Startup command: `wudod --web-uid UID --web-gid GID`. Require exactly
these two explicit numeric settings, each decimal in `1..=4294967294`; reject
missing, duplicate, unknown or nonnumeric arguments, zero and the reserved
all-ones value. Require effective UID 0 for production startup. The web UID is
the peer allowlist; GID controls access to the web socket, not authorization.
No account-name lookup, environment defaults or dynamic user-ID assignment is
part of this slice. Administrators must keep these IDs aligned with the service
account and its group memberships. Numeric IDs do not prove an account exists.

Use fixed production endpoint paths; no production endpoint override. Tests
inject temporary endpoints and expected IDs through test-only fixtures, never
a production 'skip peer check' option. Startup arguments are local admin input,
not additions to action configuration or remote message fields.

## Wire format

Use one request/response per Unix stream connection, with no multiplexing,
compression, file descriptors or streaming events.

Each frame is a four-byte unsigned big-endian payload length followed by exactly
that many CBOR bytes. The length excludes the four-byte prefix. There is no
encoding byte, format negotiation, JSON fallback or compression.

The 4096-byte payload cap applies to this status-only slice, in both
directions. Reject zero or excessive length before allocating. It is not a
permanent size decision for future WebAuthn or encrypted-secret messages: those
need schema-specific limits and a reviewed overall frame cap before addition.
A four-byte length field never authorizes arbitrary allocations.

The examples below use CBOR diagnostic notation for readability. They are CBOR
maps with text keys on the wire, not JSON text.

Request:

```text
{"version":1,"operation":"status"}
```

Response:

```text
{"version":1,"result":"ok","status":"ready"}
```

Here `ready` means only that this IPC endpoint is serving protocol requests.
The CLI should display “Daemon IPC reachable (protocol 1); action readiness not checked.”
No host paths, configuration content, users, credentials or secret metadata are
returned. There is no server software version fingerprint in this first reply.

The client writes one frame, half-closes its write side, and reads one response
frame followed by EOF. The daemon requires EOF after the request frame before
responding, rejecting extra bytes or a second frame. This avoids ambiguous
pipelining and makes trailing-data rejection testable. EOF waits are bounded
by the connection deadline; a client that never half-closes cannot hold a slot
indefinitely. This contract can change only through explicit protocol review.

Strict schemas reject unknown/missing/duplicate fields, wrong scalar types,
unknown enum values, invalid UTF-8 in CBOR text strings, and trailing data or
additional CBOR items within the frame. Version must be the unsigned integer
`1`; never coerce floats, strings or booleans, negotiate downward, or infer a
version. Typed decoders must enforce the same rules on responses and requests.

Initial CBOR profile: one definite-length flat map with text keys;
unsigned integer version and text values for the other defined fields. Reject
indefinite-length items, tags, arrays, nested maps and all other value types for
status messages. Reject duplicate keys before any map conversion can discard
them. Check declared collection/string lengths against schema limits and bytes
remaining before allocation. Emit shortest integer/length representations;
accept non-shortest representations of the same permitted unsigned integer or
definite length. Map order does not carry meaning. This protocol does not hash
or sign serialized message bytes and does not need canonical encoding.

Concrete decoder limits: requests have exactly two pairs, responses exactly
three. Text keys are at most 16 UTF-8 bytes and text values at most 32; only the
specified field names/enum values are valid. Decode version as unsigned `u64`.
Use borrowed string slices and fixed field slots with duplicate detection; do
not copy supplied strings into diagnostics. Reject wrong map size before
iterating, unknown keys without skipping their values, and any decoder position
short of the payload end. No recursive descent or `skip()` on arbitrary input.
Malformed/unrecognized keys or types take precedence over version/operation
errors. After full schema validation, check version first, then operation.

Future binary fields should use native byte strings, with explicit per-field
limits. Future encrypted/signed envelopes retain their own reviewed byte-level
contract; never assume re-serialization preserves authenticated bytes.

For authorized peers only, schema errors may receive one bounded response:

```text
{"version":1,"result":"error","code":"invalid-request"}
```

Allowed codes: `invalid-request`, `unsupported-version`, `unsupported-operation`.
Unknown fields/types/malformed CBOR use `invalid-request`; only otherwise valid
requests qualify for version/operation-specific errors. Framing errors,
unauthorized peers, exhausted capacity and timeouts close the connection with
no response. Never include input excerpts, OS/parser error text or arbitrary
client strings. Clients treat unknown response fields/codes as protocol failure.

## Inspection and logging

Use CBOR only to keep one decoder contract and one set of validation behavior.
JSON compatibility has no concrete current consumer; supporting both would add
cross-format type, binary-field and rejection-parity tests. Compression adds
another parser and expanded-size/CPU controls without a demonstrated local IPC
benefit. Both are out of scope unless a future requirement justifies review.

Operational logs describe events: bounded request type, kernel peer identity,
outcome, duration and a daemon-generated correlation ID. Never dump raw frames,
secret material or credential responses; even malformed input may contain
sensitive data. Logging is not a replacement for a packet inspector.

A future development decoder can display synthetic or explicitly selected CBOR
fixtures in readable form. That does not require JSON support on the wire and
is not an instruction to capture live secrets. No decoder tool or per-request logging
implementation is included in this slice.

## Limits, concurrency and shutdown

Use independent admission limits of four admin and four web connections,
with no application-level waiting queue. This reserves admin capacity even if
web connections saturate their slots. Acquire capacity before creating a task;
accept-and-close excess connections. Bound the kernel listen backlog as well
(16 per socket); avoid per-rejection logging under load.

Each accepted connection has a five-second absolute deadline covering peer
checks, the whole request, EOF and response writing. Do not reset it after each
byte: slow clients must not extend it indefinitely. The client has a five-second
whole-exchange deadline including connect. Parsing remains synchronous over a
small bounded payload; Tokio deadlines do not preempt arbitrary CPU work.

Use Tokio's current-thread runtime with initially `rt`, `net`, `io-util`, `time`,
`sync`, `signal` and `macros` (for `select!`/`pin!`); enable additional features only when needed. No process
feature or blocking pool work is needed for this status-only slice. Track all
connection tasks. On shutdown, stop admitting clients, close/cancel status-only
connections and await their bounded cleanup. Never reuse that cancellation
policy for future privileged actions without operation-specific review.

## Socket lifecycle and filesystem boundary

Before binding, validate the runtime directory and ancestors: trusted ownership,
directory type, no untrusted write permissions, no symlink traversal and no ACL
that grants untrusted writes. The socket path must not be supplied remotely.
Refuse any pre-existing endpoint, including a socket, rather than unlinking an
arbitrary path on startup. Stale-socket recovery is a local administrative task
for this slice; document it without adding a generic deletion operation.

Lifecycle implementation:

1. Before starting Tokio or any worker thread, set process umask to `0077` once.
   Require an existing `/run/wudo`; deployment creates it root-owned with mode
   `0755`. The daemon does not create parent directories or change their modes.
2. Open and validate directory components through descriptor-relative,
   no-follow operations. Require root ownership and no group/other write bits;
   require `/run/wudo` exactly `0755`. Reject access/default ACL xattrs on the
   runtime directory; reject access ACLs on ancestors. Treat unexpected ACL-read
   errors as failure, not absence. Document filesystem support requirements.
   Root is trusted not to swap these directories during startup or operation.
3. Preflight both endpoint names as absent. Bind admin and web sockets with
   restrictive creation permissions; never unlink an existing path, even if it
   appears to be a stale socket. Record each created endpoint's device/inode.
4. Explicitly set admin mode `0600`, web owner/group to root/configured GID and
   mode `0660`. Verify socket type, owner, mode and absence of unexpected ACLs.
   If any setup step fails, abort startup and clean up only owned endpoints.
5. Set nonblocking mode and listen with backlog 16 only after permissions are
   correct. Register both listeners with Tokio after setup succeeds. Use an
   RAII guard to clean up on ordinary startup failure and shutdown; cleanup
   checks type and device/inode in the trusted directory before unlinking.
   If identity differs, leave the object untouched and report a fixed error.

Use `rustix` safe APIs for the required Unix socket/peer/filesystem operations,
with only necessary features. No handwritten unsafe code. `minicbor`, Tokio,
`rustix` and the local protocol crate are the daemon dependencies;
no TOML, HTTP or Serde dependency is needed for this slice. Implementations must
still review actual transitive dependencies and any limitations of the selected
APIs. Do not substitute pathname-only permission checks for opened-object checks.

A crash or forced kill can leave sockets behind. Restart then fails closed;
local root must inspect/remove the stale endpoints before restarting. No remote
cleanup operation or automatic stale-socket removal. Systemd socket activation
is deferred to avoid simultaneously adding inherited-descriptor validation.
The offline config reader is not reused for this privileged lifecycle.

## Test plan and deferred work

- Root/admin and configured-web authorization matrix; all other UIDs rejected.
- Web saturation does not consume admin slots; no unbounded task/queue growth.
- Zero/oversized lengths, partial headers/bodies, extra frames and absent EOF.
- Invalid text UTF-8, malformed CBOR, huge declared lengths, duplicate/unknown/
  missing fields, unknown versions/operations and strict response validation.
- Forbidden tags, indefinite lengths, nested containers, wrong value types,
  extra CBOR items and JSON bytes; accept non-shortest encodings of permitted
  values and different map orders without changing validation results.
- Exact text/map limits, duplicate-key detection across differing length
  encodings, truncated declared strings, and version/operation error precedence.
- Slow byte delivery cannot renew deadlines; client disconnects and blocked
  readers release resources; shutdown completes within a bound.
- Symlink, wrong owner/mode, unsafe ancestor, pre-existing socket/file and
  partial-startup failures; cleanup never removes unrelated objects.
- Canary values never reach diagnostics. Status reveals no privileged state.

Run framing/handler/lifecycle tests without root using private temporary paths
and injected test identities. Document which production UID-0/ownership checks
are exercised through policy unit tests versus actual integration environments;
do not claim unprivileged tests prove privileged deployment behavior.

#12 gates WebAuthn/action invocation, not this minimal status exchange. Enrollment,
user/grant administration, configuration loading, execution, secret transport,
audit storage and richer status are separate reviewed additions. Future changes to the permission table, decoder profile, limits, startup
settings, dependencies or lifecycle require review. SECURITY.md requires
explicit review of new daemon operations, dependencies and privileged
filesystem access.

## Running the status slice

Linux with mounted `/proc` and POSIX ACL xattr query support is required.
Socket binding uses `/proc/self/fd/<directory-fd>/<name>` to anchor resolution
in the opened directory. Socket ACL inspection uses an opened `O_PATH` inode
through `/proc/self/fd`; unsupported or denied xattr queries fail closed.

Build with `cargo build --workspace --locked`. An administrator creates
`/run/wudo` owned by root with mode `0755` and no access/default ACLs, then runs
`sudo target/debug/wudod --web-uid UID --web-gid GID` using the intended web
service account's actual numeric IDs. In another terminal, run
`sudo target/debug/wudo status`. SIGINT/SIGTERM clean up owned sockets.
After a crash, inspect stale endpoints locally before removing them; do not
remove sockets belonging to a running daemon. `/run` is ephemeral, so deployment
must recreate the directory after reboot (service packaging is deferred).

Tests use current-user socket fixtures and injected expected peer identities.
They exercise kernel peer credentials, strict parsing, separate admission
limits, deadlines, client verification, shutdown and filesystem cleanup.
The separate privileged smoke test passed in a maintainer-supplied transcript:
root startup, cross-account access policy, socket permissions, duplicate startup,
and SIGTERM/SIGINT cleanup with an incomplete connection. ACL error
classification is unit-tested; filesystem compatibility remains environment-dependent.

There is no per-request audit implementation yet. Status does not load action
configuration or establish WebAuthn readiness. The web service remains a stub.

### Isolated privileged smoke test

Run:

```text
python3 scripts/ipc-smoke.py
```

The script first runs `cargo build --workspace --locked` with the repository's
`target` directory, then prompts through sudo. This keeps the CLI and daemon
binaries in sync, including after test-only builds. It requires Cargo, Linux
`unshare`, `mount`, Python 3, and mount-namespace privileges.
It mounts temporary `/etc`, `/run` and `/var/lib` directories inside a private
mount namespace, runs the production binaries, and uses child processes with
numeric UIDs/GIDs (no persistent accounts). It checks root CLI access, allowed
web access, rejection of another UID in the web group, rejection of root on the
web endpoint, socket modes, duplicate startup, SIGTERM/SIGINT, and cleanup with
an incomplete connection, plus initialization, user persistence, enrollment
open/inspect/cancel, and explicit reset. The next extension also checks user
listing, empty credential listing and missing-target inspection/revocation
failures; the maintainer confirmed that these additional checks all pass. The host's `/etc`, `/run` and `/var/lib` are not
changed. Run only trusted local builds because this test executes them as root.
The maintainer supplied a passing transcript for the expanded harness on
2026-10-05, including both shutdown signals and persistence across restart.
This validates the tested Linux environment; it does not
establish compatibility with every deployment filesystem.

## Local administration extension

The [approved administration contract](user-administration-proposal.md) adds
v2 init/upgrade/create/show on the admin socket and requires a private root-owned
`/var/lib/wudo` directory. v1 status encoding is preserved; the outer admission
cap is now 64 KiB with version/operation limits after strict dispatch. Malformed
envelopes close without a response. The updated smoke test isolates `/var/lib`
as well as `/run` and verifies persistent users across restart.


## Action/grant administration extension

The approved [action/grant contract](action-grants-proposal.md) specifies the
implemented admin-only v2 action.list, grant.create, grant.revoke and grant.list
schemas. Lists have 16 entries and an 8192-byte response cap; mutations retain
4096 bytes. The deployment smoke harness now also installs isolated trusted
configuration and checks listing, idempotent grant/revoke, unknown actions,
reset and grant persistence. These new privileged checks need a fresh run.
