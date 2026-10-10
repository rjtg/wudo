# Read-only viewing sessions: configuration and wire proposal

Status: **maintainer review completed; implementation in progress**. The product
behavior is already agreed in the [execution contract](systemd-execution-contract.md).
The maintainer approved the operations, lifetime/capacity/polling bounds and
read-only bearer-token exposure in the follow-up walkthrough. Tracking: #24; roadmap #20.

## Authority and scope

A passkey sign-in allows its user to list currently granted actions and observe
availability. It never authorizes execution, returns a reusable action grant,
or supplies privileged paths/unit names. Each action still needs a fresh
purpose-bound assertion and daemon admission checks. No session token is accepted
by action.begin/action.finish or administrative operations.

Use the existing WebAuthn verifier, exact configured RP/origin, UV and UP checks,
two-minute single-use challenges and the existing bounded assertion fields.
Before issuing a session, persist verifier metadata using the owner-bound snapshot
API from e6eea9b. Recheck expiry, owner, credential status and reset generation
on the daemon state owner after verification. A stale snapshot requires fresh
sign-in. Sign-in and action ceremony state use distinct typed purposes: even a
cryptographically valid assertion cannot finish a ceremony under another purpose.

## Accepted daemon configuration

Root-owned `/etc/wudo/wudod.toml`, read only at startup, holds:

```toml
systemctl_ack_timeout_seconds = 3
view_session_seconds = 300
```

Acknowledgement timeout accepts 1–30 seconds; viewing lifetime accepts 60–600
seconds. Missing file/fields use defaults. Reject unknown/duplicate fields,
wrong types and out-of-range values. Maximum file size is 4096 bytes. Apply the
same root-owned directory/file, no-follow, mode and ACL checks as actions.toml.
Restart is required for changes; restart invalidates sessions. No browser/client
can set these values. This replaces the earlier proposed command-line flag.

Expiry is an absolute monotonic deadline starting when a session is issued after
successful verification and persistence. Polls never renew it. Return remaining
milliseconds as a UI hint; daemon time is authoritative. At expiry clear browser
state and request a new sign-in. Do not silently reauthenticate in the background.

## Tokens and lifecycle recommendation

Generate 32 random bytes using the existing OS random source. Tokens are opaque
bearer credentials for reads only; the untrusted relay necessarily sees them.
Use a standard SHA-256 digest for daemon table lookup (existing crypto facility),
retaining only the digest, user ID, exact credential ID, deadline and poll budget.
Reject collisions without overwriting another session; never derive tokens from
public ceremony IDs or sign challenges with custom crypto. No new crypto library
is proposed.

Browser stores token only in WASM memory, never cookies, localStorage,
sessionStorage, URLs or DOM text. Best-effort clear on expiry/error/logout;
reload/closing discards it. Daemon retains the entry until expiry/revocation or
restart/reset. No logout IPC is needed initially; closing a tab does not free a
server slot immediately. Lost sign-in replies leave a bounded orphan session
until expiry; never retry finish or restore tokens from storage.

On every read, check session expiry, current owner and active sign-in credential;
then read current grants/revisions. Revoked credential invalidates its sessions;
removed grants disappear on subsequent reads. No grants is a valid empty page.
Reset invalidates pending sign-ins and sessions before mutations, including failed
reset attempts, matching existing ceremony invalidation policy. Restart clears all.
Before sending a page after asynchronous status work, recheck expiry, credential,
reset generation and current grants/revisions: omit removed grants and avoid
releasing stale authorized data. Already delivered data cannot be recalled.

## Resource budgets recommendation

| Resource | Limit/policy |
| --- | --- |
| Live viewing sessions | 128 globally, 4 per user |
| Web ceremonies | Share existing 32 globally / 2 per user across enrollment, viewing and future action ceremonies; two-minute sign-in expiry |
| Crypto jobs | Share existing global two-job verifier budget; no unbounded queue |
| Session admission | Reserve global/per-user session slot at begin; reservations count toward caps |
| Full capacity | Generic unavailable; reclaim expired entries first, never evict an unrelated valid session |
| Action page | 16 rows, exclusive action-ID cursor; maximum existing catalog 128 actions |
| Polling | UI requests visible page every 5 seconds; pause while hidden |
| Daemon read budget | One page request per session per 2 seconds; concurrent request rejected as busy |
| Unit observations | At most 4 outstanding daemon-wide, no unbounded queue, 2-second total page observation budget |

Discard a failed/expired/consumed sign-in and release its reservation. A running
verification keeps its resource reservation until completion; cancellation cannot
create an unbounded detached-work pool. Enrollment and viewing sign-in share both the aggregate ceremony and crypto
budgets; purpose-specific records remain distinct. Preserve
admin endpoint admission capacity. Unknown user/credential/capacity errors remain
generic; no guarantee of constant-time username enumeration resistance.

Poll throttling may briefly delay page navigation; the UI retains the current
page and waits. Never auto-repeat a mutation. If status collection exceeds its
budget, report affected observations as unknown and disable those actions.
Do not claim a service/job timed out merely because its status query did.
Systemd queries/alias handling still depend on the adapter review.

## Proposed v2 IPC messages

Keep existing framing, strict maps, duplicate/unknown-field rejection, endpoint
peer checks and per-connection deadlines. All three new operations are web-socket
only. Existing root-only `action.list` is unchanged and must not be relayed.
Names below are proposals; no existing codec row is silently repurposed.

| Operation | Request body | Success body | Request/response byte caps |
| --- | --- | --- | --- |
| `view.begin` | `{user_name: Name}` | `{ceremony_id, remaining_ms, options: RequestOptions}` | 4096 / 24576 |
| `view.finish` | Existing assertion-finish fields | `{token: bytes(32), remaining_ms: 1..600000}` | 12288 / 4096 |
| `view.actions` | `{token: bytes(32), ?after: ActionId}` | `{remaining_ms: 1..600000, actions: [ViewAction], ?next_after: ActionId}` | 4096 / 16384 |

There are **three** new operations. Status is included in `view.actions` rather
than exposing a separate arbitrary-unit status primitive. `view.begin` uses the
existing RequestOptions shape: RP ID, challenge, timeout, bounded allowCredentials
and required user verification; no PRF/extensions added. `view.finish` uses only
ceremony ID, credential ID, original client/authenticator data, signature and
optional owner-bound user handle, as specified by the existing assertion profile.
No username or session token selects a finish principal.

`ViewAction` has exactly:

```text
{action_id: ActionId, description: text(1..256), revision: bytes(32),
 confirmation: bool,
 state: "active" | "inactive" | "failed" | "transitioning" | "unknown",
 availability: "available" | "already-running" | "already-stopped" |
               "busy" | "state-unavailable" | "unsupported"}
```

Description uses existing nonblank/control-free rules. No raw systemd property,
unit name, object path or journal string is exposed. Return only current grants.
For unsupported operations/prerequisites return state unknown/unsupported; never
probe LUKS or skip prerequisites. A failed unit supports Start but not Stop;
for Stop on failed state return already-stopped. State active includes active
(exited). Pending jobs and in-flight submissions produce busy. Unknown or
unmapped states produce state-unavailable. Availability is a hint, never authority.

Pages are sorted strictly by action ID after the supplied cursor. `next_after`
is present only with a full 16-row page and known additional row and must equal
the last ID. Readers validate order, duplicates, cursor and enum values. Pagination
is not a snapshot across pages; grants may change. Browser replaces each displayed
page rather than retaining previously authorized actions indefinitely.

Use fixed existing error categories: invalid-request, unsupported-operation,
not-permitted, unavailable, verification-failed, busy and internal-error.
Map stale metadata conflicts to unavailable on this web endpoint (conflict remains
admin-only); failed cryptographic checks use verification-failed. Missing/expired/revoked sessions all map to unavailable. Return no token,
record data, SQL, systemd error or principal existence explanation on failure.
All error/response sizes must receive maximum-field codec tests before activation.

## HTTP/browser integration recommendation

Extend the current bounded relay with POST `/api/view`, application/cbor only,
allowlisting exactly the three operations above. Token is in the CBOR POST body,
never query parameters, Authorization headers or cookies. Retain strict same-origin
Host/Origin checks, no CORS/compression, no-store responses, CSP, fixed errors,
root-daemon peer verification and no automatic relay retries. Route body limit
12288 bytes, response bounded by operation, existing shared HTTP admission limits.
Do not log request/response bodies or tokens. Enrollment route remains restricted
to registration operations. No generic IPC proxy is introduced.

UI asks for username then passkey sign-in. Show authorized actions disabled with
reasons until observations establish availability. While a poll is in flight,
or after poll failure, disable controls rather than displaying stale availability.
A busy response backs off to the normal interval; unavailable clears the token
and list and requests sign-in. Do not claim polling makes subsequent execution
safe: action admission always rechecks state, grants and credentials.

## Required tests and implementation gates

Before runtime activation, review this proposal under SECURITY.md for new IPC,
session authority and bounds. The already approved read-only session concept does
not implicitly approve every numeric limit or field here.

Tests must cover purpose confusion between registration/view/action ceremonies,
forged/malformed tokens, replay, expiry during crypto/status queries, UV/UP/origin
failure, old metadata snapshots, revocation/reset at commit, capacity reservations,
no-change verifier results, lost finish reply, restart, wrong user/credential,
grant removal during observation, duplicate/oversized fields, maximal pages,
poll throttling, unknown state, admin-operation relay denial and zero token logs.

Implementation sequence within #24:

1. Review configuration, bounds, schemas and bearer-token exposure as one package.
2. Implement codec/config and negative tests, with runtime handlers disabled.
3. Implement bounded sign-in/session state using the metadata API. Initially
   report state-unavailable until a reviewed systemd adapter supplies observations;
   do not enable action execution or advertise available actions prematurely.
4. Connect filtered pages/status projection and Rust/WASM sign-in/polling, then
   add isolated browser tests. Real systemd observations depend on the adapter;
   action admission and execution remain separately gated.


## Codec implementation progress

The v2 codec now defines `view.begin`, `view.finish`, and `view.actions`, restricted
to the web endpoint. Begin uses the existing bounded authentication challenge
shape; finish returns a 32-byte token and absolute remaining lifetime (at most
600000 ms). Actions returns at most 16 sorted entries with ID, description,
32-byte revision, confirmation flag, unit state and availability. Pagination
cursors must match the last entry of a full page. Unknown states/fields, invalid
token lengths and inconsistent availability fail validation.

Action submission responses retain the existing opaque local `operation_id` and
add `outcome-unknown` alongside `accepted`. The ID is correlation only, not a
systemd job ID or a promise of execution-history lookup. Neither outcome is
service completion or health. This codec support does not enable daemon handlers,
authentication, sessions, HTTP routes or UI controls; those remain pending.

## Daemon state and IPC implementation

Daemon `view.begin`, `view.finish`, and `view.actions` handlers are implemented.
They use the root-configured lifetime, owner-bound credential snapshots, the
established verifier, and serialized durable metadata commits before token issue.
Single-use state is specific to viewing: action/registration finish cannot consume
it. Sessions retain token digests only, have absolute deadlines and fixed capacity,
and recheck active credentials/current grants on reads. Reset invalidates pending
and active state before attempting the mutation; restart retains neither.

Enrollment and viewing now share lease-based ceremony (32 globally, 2 per user)
and crypto (2 globally) capacity. Running jobs retain leases across cancellation
and reset until their results are dropped/completed. The existing worker thread
limit and bounded queue remain in place; no crypto runs on the I/O thread.

This slice deliberately returns unknown/state-unavailable for supported systemd
operations and unknown/unsupported for other operations/prerequisites. It does
not launch backend queries or submissions. HTTP routes and WASM sign-in/polling
are not connected yet. The next integration must recheck credentials and grants
after asynchronous observations before releasing results. Shared action ceremony
admission must use these same budgets when action handlers are added.

Validation includes signed soft-authenticator tests for replay, purpose isolation,
wrong origin/signature, expiry, stale snapshots, revocation before commit, grant
removal, throttling, reservations and orphan-session capacity; daemon IPC tests
exercise sign-in, revocation, reset and restart-scoped tokens. This is synthetic
verification and IPC evidence, not browser or real-authenticator validation.
