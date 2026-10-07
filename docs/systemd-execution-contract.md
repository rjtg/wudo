# First systemd action execution contract

Status: user-facing policies below were agreed with the maintainer in the design
walkthrough. This document consolidates those decisions for review; runtime is
not implemented. Technical details explicitly marked open are not implied approvals.
Tracking: [#24](https://github.com/rjtg/wudo/issues/24).
Parents: #5, #12, #16; roadmap #20. Prerequisite: action catalog and grants #23.

## Scope

Support administrator-configured `systemd-start` and `systemd-stop` operations on
fixed units, without prerequisites or secrets. Clients select action IDs, never
unit names, executables, arguments or environment. Start and Stop are separate
capabilities with separate grants. Defer restart, LUKS, PRF, secret transport,
application health probes and live SSE progress. Unsupported action shapes must
remain unavailable; never skip a configured prerequisite to fit this slice.

## Acceptance, completion and ownership

After authenticating and admitting an action, wudod submits the fixed operation
to systemd. Report **request accepted** only when systemd acknowledges acceptance.
This is not proof of successful completion. Successful completion means systemd
reports that the requested job completed successfully, not that an application
is healthy or its HTTP interface is usable. Future integration types can define
their own completion criteria, including submission-only behavior.

Systemd owns jobs, service lifetimes and startup/shutdown timeouts. Wudo does not
cancel jobs, stop services or undo effects because the browser disconnects, a
Wudo observation deadline expires, or the daemon restarts. Admitted work proceeds
independently of the browser connection. Before admission, existing ceremony
expiry and cancellation rules still apply.

Wudo's communication with systemd must be bounded. A missing acknowledgement
means **could not confirm acceptance**, not that nothing happened. Never retry
a submission automatically, including after disconnect or daemon restart.
Refresh current state; a manual retry is a new action requiring fresh verification.
Do not implement a durable replay queue or claim exactly-once execution across
SQLite and systemd. A crash can leave the outcome unknown.

For this slice, acceptance feedback plus current unit-state polling is enough.
Persistent task history and per-job progress retrieval are not required. Current
unit state is an observation, not proof of a particular request's outcome.
A short-lived oneshot may complete and return to inactive between polls.

## Availability and concurrency

Only show actions currently granted to the viewing user. Show unavailable
eligible actions disabled, with a short reason; hide ungranted actions.

| Operation | Eligible unit states | Other required conditions |
| --- | --- | --- |
| Start | inactive or failed | No pending job or conflicting Wudo submission |
| Stop | active, including active (exited) | No pending job or conflicting Wudo submission |

Transitioning, unknown or unqueryable state disables operations. Unsupported
states fail closed. Status polling updates the buttons but never authorizes an
operation. The daemon rechecks availability immediately before submission. A
state mismatch returns **action no longer available**, rather than treating a
redundant operation as successful.

Reject conflicts as **unit busy; try again**; do not queue them. This applies
across action IDs and users targeting the same unit. Observe jobs submitted
outside Wudo too. Do not replace a conflicting pending systemd job. A job that
outlives Wudo's observation period still prevents conflicting operations while
pending; a disconnected client must not release an in-flight submission guard.

Root and other services can race the final state check. The check and systemd
submission are not atomic with outside administrators. The maintainer accepts
that residual race; systemd handles changes after the check. Re-query after
uncertainty and fail closed when current availability cannot be established.

## Authentication and admission

Each Start/Stop invocation requires a fresh, single-use action-bound assertion,
verified by wudod through the established WebAuthn verifier. Bind the principal,
action ID and current action revision in daemon-held ceremony state. Viewing
sessions do not substitute for this assertion. Require user presence and user
verification under the existing origin/RP policy.

After verification, independently recheck credential ownership/active status,
current grants and action revision. Persist required verifier metadata before
privileged submission; storage failure prevents submission. Grant or credential
revocation before admission prevents admission. Already admitted jobs are not
undone by later revocation. The implementation must specify the serialized
admission boundary and metadata concurrency behavior before enabling handlers.

## Read-only viewing sessions

A separate daemon-verified passkey sign-in permits listing the user's granted
actions and polling their unit states. This is a limited exception to earlier
no-session wording: **no session may authorize execution**. Sign-in must be
purpose-bound separately from action ceremonies; neither assertion nor token
may be reused for the other purpose.

Agreed lifecycle:

- Administrator-configurable lifetime owned by wudod; default five minutes.
- Absolute expiry from successful sign-in; polling does not extend it.
- Token lives only in browser memory: no cookies, local/session storage or URLs.
  Reload or closing the page requires a new sign-in.
- Daemon sessions live only in memory; restart invalidates all of them.
- Bind each session to the authenticated user and exact sign-in credential.
- Every list/status request checks expiry, current credential status/ownership
  and current grants. Revocation invalidates the session; removed grants disappear
  on the next poll. Installation reset must invalidate sessions as well.

The web relay remains untrusted. A viewing token conveyed through it is not
end-to-end secret transport and must confer no execution authority. Treat tokens
as sensitive bearer material: never log them, put them in URLs or error messages,
or persist them. Poll results already displayed cannot be retroactively erased
by revocation. A compromised UI/relay can misrepresent state; daemon admission
checks remain authoritative.

## Feedback

Use bounded fixed outcomes such as request accepted, action no longer available,
unit busy, service failed, and could not confirm acceptance, plus current state.
Detailed service logs remain in the local journal. Do not relay raw journal
entries, child output, systemd error strings or configuration paths to browsers.
Polling is the initial transport; SSE may be added later without changing job
ownership or authorization. Polling failure means unavailable/unknown, never an
assumption that the unit stopped.

## Technical details still to specify before implementation

These are engineering follow-ups, not unresolved user-facing behavior:

- Select and review the systemd interface/dependency, bounded calls, non-replacing
  job submission, canonical unit identity/aliases, and authoritative pending-job
  checks. Locks must not be bypassable through two names for the same unit.
- Define exact daemon-owned session configuration location, accepted lifetime
  range, token construction, session/ceremony caps, eviction and response sizes.
  Do not introduce an unbounded session table or unauthenticated status oracle.
- Specify strict sign-in/list/status IPC schemas, HTTP allowlist and token
  transport, page limits, polling frequency/backpressure, and safe error mapping.
- Define durable authentication metadata updates and concurrent assertion rules,
  reset/revocation ordering, and the admission-to-submission lifecycle.
- Reconcile the reserved action.finish response/operation_id with acceptance-only
  feedback. Do not invent a receipt that is an execution token or imply a durable
  history. Specify the reply when submission acknowledgement is uncertain.
- Resolve existing `timeout_seconds` and `output_limit_bytes` for systemd actions.
  They must not become service/job cancellation budgets. Communication deadlines
  are needed, but their numbers and config migration policy are not yet approved.

The earlier overall execution-timeout proposal and reserved action wire schema
must be updated before code enables this contract. No implementation may silently
ignore those fields or reinterpret them as health checks.

## Implementation slices and acceptance checks

1. **Credential metadata persistence:** bounded transactional update API and tests
   for concurrent verification, revocation/reset races, failures and reopen.
   No action handlers yet.
2. **Viewing-session wire/config contract and implementation:** purpose-bound
   sign-in, five-minute default, root configuration, bounded session storage,
   owner/grant-filtered pages and expiry/revocation/reset tests. Review exact
   schemas and dependency changes before enabling them.
3. **Systemd adapter and admission:** resolve the remaining interface/timeouts
   and receipt details, then implement bounded status/submission and serialized
   admission. Test same-unit conflicts, aliases, external jobs, state races,
   unknown status, stale revisions, failed persistence and lost replies.
4. **Browser integration and isolated E2E:** sign-in, disabled actions with
   reasons, polling, fresh verification for each operation and explicit uncertainty.
   Test a disposable unit through start/stop, browser disconnect and daemon restart.
   Keep real host services untouched.

Test purpose confusion/replay, expired sessions, cross-user access, unauthorized
and revoked callers, unknown fields/actions/states, session capacity, browser
reload, and polling that never extends lifetime. Verify no automatic retries or
job cancellation occur. Keep systemd integration tests isolated from host units;
synthetic adapter tests alone do not prove a real systemd deployment works.
