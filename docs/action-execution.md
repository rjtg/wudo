# Action authentication and submission

Implemented under [#24](https://github.com/rjtg/wudo/issues/24). This connects the
reviewed [systemd contract](systemd-execution-contract.md) and
[backend policies](integration-backends.md); it introduces no new operation types.
Real systemd/container and physical passkey validation remain outstanding.

## Authority and ordering

`action.begin` accepts only a user name and configured action ID. The daemon
checks the current revision-bound grant and rejects unsupported action shapes,
including prerequisites and secrets. It creates a two-minute WebAuthn ceremony
bound internally to that user, action revision and fixed typed operation.
`action.finish` consumes that ceremony before verifier admission. Viewing and
enrollment messages cannot consume action state; viewing tokens never authorize
an operation. Verification uses webauthn-rs, exact configured RP/origin, user
presence/verification and the original assertion bytes.

On the serialized state owner, successful verification rechecks the grant and
commits owner-bound credential metadata. An off-owner worker then resolves the
unit's canonical identity, acquires its guard and rechecks identity/state/job
availability. It retains both the guard and worker slot while sending the
prepared operation back to the state owner. The owner rechecks installation
invalidation, ceremony and exchange deadlines, active owner-bound credential,
current grant and exact action revision. The owner then consumes this authority
and hands the admitted operation back through a capacity-one channel. This
handoff is the admission boundary, serialized with local administration.

The same backend worker makes one fixed submission and returns a bounded reply.
No browser-selected executable, argv, unit name, backend or environment enters
this path. No queue of accepted actions, automatic retry, receipt database or
job cancellation is added. A later reset/revocation cannot revoke an already
admitted operation; a crash or disconnect may leave acceptance unknown.

## Bounds and outcomes

Enrollment, viewing and action ceremonies share 32 global / two per-user leases
and two verifier slots. Action authority retains its ceremony lease through
preflight and submission. Observations and action backend work share at most
four workers, with no waiting admission queue. The canonical unit guard remains
held through submission and client cleanup. Shutdown terminates Wudo's own
systemctl client, never a systemd job, and bounds backend-worker waiting to two
seconds; stuck cleanup retains its slot/guard in the bounded detached worker.

Only zero exit with complete bounded output collection and stable executable
identity yields `accepted`. Ambiguous post-spawn failures yield `outcome-unknown`.
A definite failure before spawning yields an unavailable error. `operation_id`
is a fresh random correlation value, not an execution token, job ID, durable
receipt or completion claim.

IPC headers, payload and half-close retain their five-second read budget. Only
a fully decoded `action.finish` receives a separate 35-second response budget,
covering the root-configured acknowledgement timeout (one to 30 seconds),
preflight and verifier work. Ordinary IPC remains five seconds. Expiry before
admission rejects work; expiry after admission cannot undo a submitted job.

`POST /api/action` allowlists only `action.begin` and `action.finish`. Existing
host/origin, content-type, strict CBOR, root-peer and no-store checks apply.
The relay allows 40 seconds only for action finish; other exchanges retain five
seconds. HTTP body reads are bounded to five seconds and headers to three.
Connections retain ten seconds normally; only a validated action finish can
extend that to 50 seconds. Browser fetch allows 55 seconds for finish and ten
otherwise. A reverse proxy must allow at least that response duration.

## Browser behavior

The Rust/WASM UI shows available actions with a Run button and unavailable ones
with a disabled button and reason. It uses the signed-in user name, honors the
configured UX confirmation, and obtains a fresh action assertion on every click.
It prevents overlapping local invocations, stops polling during the invocation,
and refreshes state afterward. It never treats a viewing session as execution
authority. Sign-out/expiry before sending finish prevents that local submission;
a finish already sent may have run even if the page closes.

Feedback distinguishes request acceptance from service completion. Missing or
uncertain replies ask the user to check current state before a manual retry.
Polling does not overwrite the last submission feedback or retry the operation.
The accepted malicious-UI risk remains unchanged.

## Validation boundary

Automated coverage includes genuine signed assertions, single consumption,
purpose isolation, unsupported/ungranted actions, revision changes, expiry,
credential revocation, metadata conflicts, reset/generation checks, retained
leases after admission, IPC grant removal and restart, route separation, and
an HTTP response exceeding the ordinary deadline only for action finish.
Backend tests separately cover canonical guards, state parsing, executable trust,
bounded subprocess collection and shutdown. Tests do not start or stop host units.

The existing disposable browser harness checks enrollment/viewing and disabled
controls without a systemd manager. It does not yet prove start/stop submission.
Real-systemd tests for start/stop, aliases, external jobs, disconnects and restart,
and real-authenticator/Pi validation remain necessary. Do not treat compilation
or synthetic backend tests as those deployment results.
