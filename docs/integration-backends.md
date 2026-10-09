# Internal integrations and the first systemctl backend

Status: the maintainer accepted the integration architecture and systemctl-first
choice. Concrete subprocess, parser and budget recommendations below are a
**reviewable proposal, not implemented or implicitly approved**. Tracks #24,
with the [execution contract](systemd-execution-contract.md).

## Accepted architecture

Use a general internal integration facade with compile-time Rust implementations.
An integration describes a supported facility, such as systemd or later LUKS.
A backend is one implementation of that integration: systemctl initially, a
possible D-Bus implementation later. This is not a dynamically loaded plugin API,
command-template language or generic secret-to-command facility.

The common surface is deliberately small: observe availability and submit a typed
operation, returning structured outcomes. Keep operation-specific data in closed
Rust enums/structs, not strings plus arbitrary argument maps. Systemd operations
are Start/Stop of a trusted configured unit. LUKS provisioning, secret transport
and device checks require dedicated typed APIs and later review, not a generic
secret parameter bolted onto every integration.

Daemon code owns authentication, grants, ceremony/revision binding, admission,
resource budgets and concurrency. The facade receives only a validated operation
from trusted configuration. Observation is not authorization; submission is not
proof of eventual completion. Integrations cannot mint credentials, sessions or
grants. Integration-specific availability rules belong to typed integration
logic; systemctl parsing and process handling belong to its backend.

Use a closed dispatch enum initially; a small Rust trait for substituting a test
backend is acceptable where useful. Avoid a general registry, dynamic ABI or
premature framework. Root-selectable backend configuration can follow when a
second implementation passes the same behavioral contract tests. Only systemctl
exists initially: no ineffective selector, configurable executable or automatic
fallback. Future backend changes must preserve authorization and availability
semantics; transport failure must never trigger a second submission via fallback.

## Proposed internal shapes

Illustrative design, not final Rust signatures:

```text
ConfiguredOperation = Systemd { unit: validated UnitName, verb: Start | Stop }
Observation = { target: ResourceKey, state, availability }
Submission = Accepted | NotSubmitted(reason) | OutcomeUnknown
ResourceKey = Systemd(canonical_unit_id)   // future variants added explicitly
```

Backend resolution/observation supplies canonical identity to daemon concurrency
control. A private admitted-operation type, constructible only by daemon admission
code, should cross the submission boundary. It binds the operation, action revision
and resource guard. It is not an IPC token and must not be serializable.
A mock backend substitutes only in tests; production configuration cannot enable it.

## Proposed fixed systemctl command set

Always launch the absolute `/usr/bin/systemctl` directly, never through a shell.
Below, UNIT is exactly one validated administrator-configured unit argument:

```text
/usr/bin/systemctl --system --no-pager --no-ask-password show --all --property=Id,LoadState,ActiveState,Job -- UNIT
/usr/bin/systemctl --system --no-pager --no-ask-password --no-block --job-mode=fail start -- UNIT
/usr/bin/systemctl --system --no-pager --no-ask-password --no-block --job-mode=fail stop -- UNIT
```

Only those fixed verbs/options are allowed. No --user, host/machine selection,
remote bus address, patterns, arbitrary arguments, enable/disable, restart,
reset-failed, cancel or kill. Existing restricted unit-name validation applies.
Service and target dependency behavior remains trusted systemd configuration;
Wudo does not reproduce or bypass that dependency graph.

The upstream manual describes no-block as returning after verification/enqueuing,
and job-mode=fail as rejecting conflicts with pending jobs. Therefore a successful
nonblocking invocation supports acceptance feedback, not completion feedback.
Compatible jobs can still merge in an external race; no atomic check-and-submit
claim is made. [systemctl manual source, v257](https://github.com/systemd/systemd/blob/v257/man/systemctl.xml).

## Proposed observation parser

Request just four properties and retain property names. Bound stdout to 4096
bytes, total stdout/stderr to 16384 bytes, each line to 512 bytes and line count
to 8. Parse UTF-8 `key=value` lines, permitting arbitrary property order but no
duplicates, extra keys, NUL, additional records or missing values except Job.
Require exactly one occurrence of each requested property. Permit normal final
newline; reject malformed framing and overflows. Never parse localized `status`
output or journal text.

- Id: validate with Wudo's unit grammar; use as canonical concurrency key.
- LoadState: only loaded is initially operable; all other known or future values
  make the action unavailable. Unknown state never silently becomes inactive.
- ActiveState: active, inactive and failed map to agreed rules. activating,
  deactivating and reloading map to transitioning. Any other value is unknown.
- Job: empty value means no pending job; a positive decimal u32 means pending.
  Zero, signs, nonnumeric text and overflow are invalid under this initial profile.

The v257 show implementation renders Job as the numeric ID when positive and an
empty property otherwise. This is source evidence for a parser fixture, not proof
of compatibility with every installed release.
[Upstream show implementation](https://github.com/systemd/systemd/blob/v257/src/systemctl/systemctl-show.c).

Check the show exit status and complete bounded output before trusting any field.
A query timeout or malformed/nonzero response means state unavailable. Never expose
raw stderr or invent detailed systemd failure classifications from human messages.
Pin supported fixture variants in tests and validate the actual Pi/container
systemd versions before claiming deployment compatibility.

## Canonical identity and conflicts

Resolve the configured name to Id, acquire a non-waiting daemon-wide guard on that
canonical systemd ID, then re-observe under the guard. If identity changed, fail
closed; do not chase names in a loop. Recheck current action/grant/credential and
revision through the state owner before admission. Use the resolved validated ID
as the single submission unit; it came from resolving trusted configuration,
never from the browser. All action IDs/users resolving to that ID share the guard.

The guard covers final observation through subprocess completion/cleanup and is
independent of the requesting connection. Reject a pending Job before submitting;
job-mode=fail protects the later conflicting-job race. After successful submission,
subsequent availability checks consult systemd's pending job/state. The guard does
not need to remain held for the lifetime of a systemd job. An external privileged
administrator can still change aliases/state after checks; that is the already
accepted race. Never infer a pending job disappeared merely because a client left.

## Proposed process and executable trust policy

Validate the fixed executable through no-follow descriptor traversal of `/usr/bin`
and its ancestors. Require root ownership, no group/world writes, no access/default
ACLs; leaf must be a regular executable owned by root, not setuid/setgid, without
file capabilities. Reject a symlinked executable in the initial supported layout;
document that unsupported distro layouts require review, not PATH fallback.
Recheck identity before spawning and after completion; root package replacement is
a trusted administrative race, not an untrusted-writer boundary. If identity cannot
be established, disable backend operations. Do not weaken checks for tests.

Trusted root package contents, dynamic loader/libraries and systemd unit definitions
remain part of the host trust base; checking systemctl is not executable attestation.
Use isolated root-owned fixture directories/containers for production-path tests.

Clear inherited environment. Set only fixed LC_ALL=C, LANG=C, PATH=/usr/bin:/bin,
SYSTEMD_COLORS=0 and SYSTEMD_PAGER=cat, retaining explicit no-pager/no-ask-password.
In particular do not inherit DBUS_*, SYSTEMD_* overrides or loader injection vars.
stdin is /dev/null; stdout/stderr are separate bounded pipes, drained concurrently.
No terminal, secret input, source error text in logs, or inherited privileged FDs.
Use existing Tokio with its process support if practical; dependency/feature diff
must be reviewed during implementation. Prefer safe Rust APIs, no pre_exec hook.

## Proposed deadlines, cleanup and results

Observation deadline: two seconds including pipe reads and process exit, constrained
by the page's overall budget. Submission communication deadline:
`min(action.timeout_seconds, 3 seconds)` from spawning, not a systemd job lifetime.
Cap global subprocess admission at four with no waiting queue. The deadline must
not slide on partial output. Drain both streams up to the total hard cap; exceeding
it terminates and reaps the client process. Never buffer unbounded output.

Terminate/reap only Wudo's systemctl child on deadline/shutdown. This is transport
cleanup, not cancelling a systemd job; never invoke cancel/stop/kill as rollback.
Keep the guard/resource slot until cleanup is established. If reaping cannot be
confirmed promptly, quarantine the slot and target rather than create unbounded
untracked children. State unknown cannot restore availability. Exact Rust cleanup
mechanics and shutdown bounds need tests before handlers are enabled.

| Evidence | Internal outcome |
| --- | --- |
| State/grant check failed, capacity unavailable, or spawn definitely failed | NotSubmitted, fixed reason |
| Child exited zero with complete bounded collection and stable executable checks | Accepted |
| Nonzero exit after spawn, signal, timeout, lost pipe, overflow, or uncertain transport | OutcomeUnknown |

Treat a post-spawn nonzero exit conservatively: systemctl text is not a reliable
machine-readable guarantee that no request reached the manager. It may be a clear
rejection internally, but the first adapter need not parse that text to claim it.
Never retry automatically or return a fake systemd job ID. A Wudo receipt, if kept
in the wire contract, must be a local correlation ID only; receipt/message schema
still needs separate review. Current state is not a historical execution receipt.

## Existing configuration fields: proposed interpretation for review

Systemd owns job timeouts. For schema-1 systemd actions, propose that
`timeout_seconds` caps only the submission exchange, subject to the smaller fixed
three-second ceiling. It never causes service/job cancellation. Observation has
its own fixed budget. `output_limit_bytes` bounds service output exposed by Wudo;
this backend exposes none (zero), satisfying all configured values. Fixed bounded
systemctl protocol/diagnostic pipes are internal transport data and are never
returned as service output. Document this distinction before enabling execution.

This is a concrete alternative to immediately introducing a new action schema.
It changes the earlier proposed overall-execution-budget meaning, so it requires
explicit review. Do not silently implement it. A later schema may remove irrelevant
systemd fields while keeping integration-specific execution limits elsewhere.

## Validation and next slices

No host start/stop commands were executed for this investigation. Evidence is the
upstream manual/source, not a real-systemd E2E result. No production Rust/dependency
changes in this document-only slice.

1. Review subprocess trust/deadlines, config-field interpretation and output/result
   policy together. Architecture and systemctl-first choice are already accepted.
2. Add isolated parser/process runner tests: missing/duplicate/unknown fields,
   empty versus missing Job, oversized output, concurrent stdout/stderr, timeout,
   nonzero/signal, hostile inherited environment, executable symlink/ACL/mode checks,
   alias convergence, identity changes and caller disconnect without releasing guard.
3. Implement typed facade and systemctl backend without enabling remote execution.
   Apply identical contract tests to future implementations.
4. Connect admission only after grant/revision/credential serialization and wire
   acceptance/uncertainty semantics are reviewed. Validate against a disposable
   real systemd manager, including external pending jobs and dependency conflicts.
   Browser and Pi validation remain distinct follow-ups.
