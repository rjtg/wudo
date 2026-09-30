# Daemon-side WebAuthn ceremonies

Status: **draft for review, not approved for implementation**.
Tracking: [#12](https://github.com/rjtg/wudo/issues/12).
This extends the reviewed status-only IPC design; it does not add operations or
dependencies. The explicit `enroll --insecure` opt-in is an accepted design
decision, as are the installation-configured origin/RP rule and one fresh
verification per action. Other policy
choices remain proposals unless recorded in SECURITY.md. Secret transport remains #13 and device/PRF feasibility #14.

## Verifier and origin policy

An [isolated verifier experiment](../experiments/webauthn/README.md) now exercises
synthetic registration/authentication and rejection cases. Its findings inform
this draft; no verifier dependency or operation has been added to the daemon.

Propose `webauthn-rs` using its high-level passkey registration/authentication
APIs inside `wudod`. The inspected documentation is version 0.5.5. Its API
provides paired challenge and server-state objects; keep that state exclusively
in the daemon. Do not serialize it into browser cookies or trust state supplied
by the relay. Passkey APIs require user verification. Registration must reject
a credential ID already belonging to any account, not merely duplicates within
the selected account. Update stored authentication metadata after verification.
See the [library API](https://docs.rs/webauthn-rs/0.5.5/webauthn_rs/struct.Webauthn.html).

Before adding the dependency, inspect locked features, cryptographic backend,
transitive dependencies, Linux ARM support, supported algorithms, and extension
handling. No handwritten signature, attestation or authenticator-data parser.
Do not enable relaxed verification or dangerous state-serialization features.
An API suitability spike must verify the proposal against the selected version.

Accepted installation policy: the administrator configures one HTTPS origin
and an RP ID equal to that origin's hostname. Wudo hardcodes no installation
hostname or domain. Match scheme, host and effective port exactly; no wildcard,
subdomain or any-port acceptance. These are trusted daemon settings, separate
from the web service's bind address. Configuration syntax and URL normalization
rules remain to be specified before implementation.

Proposed additional restriction: reject cross-origin iframe ceremonies and
alternate/native-app origins initially.
Never derive these settings from Host/Forwarded headers or a client message.
RP/origin changes invalidate pending ceremonies and require local migration
planning; changing RP ID can require re-enrollment. HTTPS termination may be
external, but does not alter the daemon's configured browser origin.

The [builder API](https://docs.rs/webauthn-rs/0.5.5/webauthn_rs/struct.WebauthnBuilder.html)
exposes origin and port policy controls. Verify their exact defaults and tests
rather than assuming URL validation alone enforces this deployment policy.

Require both user presence and user verification for registration and every
action assertion. Accept ordinary passkeys without manufacturer attestation;
do not require hardware-only credentials or forbid synchronized credentials.
Request no attestation identifying a device model as an authorization condition.
Authenticator portability and PRF availability must still be tested in #14.

## Identity and normal action flow

Initial flow is account-first: the browser supplies a user selector and action
ID. These are untrusted lookup hints. Do not expose an unauthenticated directory
of users or credentials. Return a generic unavailable result for invalid user,
action or grant combinations; identical timing/enumeration resistance is not
claimed. Discoverable/usernameless login is deferred.

1. Resolve an active user, current grant and configured action. Select only that
   user's active credentials. Let the library generate the WebAuthn challenge.
2. Store a daemon-generated opaque ceremony ID with verifier state, purpose,
   immutable user ID, action ID, action/configuration revision, policy revision,
   RP/origin revision, allowed credential identities and monotonic expiry.
   Public ceremony IDs are correlation handles, never bearer authorization.
3. Return public request options and ceremony ID. Release the IPC connection;
   the five-second connection timeout is separate from the human ceremony TTL.
4. Finish accepts the ID and bounded assertion, not a replacement user/action.
   Atomically remove the pending state before verification. Even a failed
   verification consumes this ceremony. Concurrent finishes have one winner.
5. Verify through the library, resolve the returned credential to its current
   owner, require membership in the bound credential set, and recheck active
   user, credential, grant and matching configuration/policy revisions.
6. Persist required credential metadata before admitting the bound operation.
   Failed persistence means no action admission. Serialize updates for a given
   credential so two ceremonies cannot overwrite counter/revocation metadata.

Reject assertion counter regressions where counters are supported, including a
positive stored counter followed by zero. All-zero counters are not themselves
replay evidence; the single-use challenge remains mandatory. Treat anomalous
non-incrementing positive counters as a failed attempt requiring local review,
not an automatic permanent account deletion. Verify library behavior and test
against synchronized credentials before finalizing this policy. See
[WebAuthn verification](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion).

Accepted: each action invocation requires one fresh passkey verification bound
to that action. One invocation covers its configured internal steps: unlocking
storage and starting Paperless does not require two separate verifications.
A later invocation requires a new challenge and assertion, even for the same
action. No reusable login session, web-issued grant or generic authorization
token authorizes subsequent privileged actions.

Accepted malicious-UI risk: a compromised relay can obtain a genuine challenge
for an action the user is authorized to invoke while displaying a different
action. The daemon still verifies the assertion, enforces grants and executes
only the action bound to that challenge, but cannot prove what the user saw.
For example, the UI might show Start Paperless while requesting Stop Paperless.
Confirmation is a UI affordance, not a trusted boolean in the protocol.

Keep the server-held challenge/action binding; do not add daemon signatures to
challenges to try to authenticate displayed action text. Malicious served code
could ignore signature verification or display a misleading description of an
authentic signed challenge. UI attestation and an independently trusted action
confirmation display are out of scope. This does not resolve or remove the
separate requirement for authenticated secret transport in #13.

## Enrollment and recovery

Accepted convenience option: local root may initiate enrollment with
`sudo wudo enroll --insecure` (target-user argument syntax remains to be
specified). This deliberately skips candidate-specific local approval and
independent credential identification. During that short-lived opportunity,
the first successfully verified registration through `wudo-web` is activated
for the user selected by root. No pre-known device ID or fingerprint comparison
is required. This is a one-enrollment exception, not a daemon-wide insecure mode.

The daemon still generates and verifies the actual WebAuthn ceremony, including
challenge, origin/RP policy and the required authenticator checks. "Insecure"
does not disable signature verification, permit arbitrary user selection, add
grants, or make the first browser an administrator. The local command is the
authority to enroll; the browser is only supplying the new credential.

Accepted risk: any party reaching this opportunity, including a compromised
relay, can race the intended person and register an attacker-controlled passkey.
That credential gains the selected user's existing action grants, though not
automatically any downstream secret wrappers. The CLI must make this consequence
visible when opening the window. No second approval prompt is required in this
explicitly selected mode. Default enrollment retains local candidate approval.

Proposed mechanics to refine before coding: one outstanding insecure opportunity
at a time, discoverable by the web relay without a separately transferred ticket;
root fixes its target user and expiry. Atomically activate at most one verified
candidate and close the opportunity. Expiry, local cancellation and restart close
it too. Concurrent verification must recheck the opportunity at commit; losing
candidates cannot activate. Invalid attempts never activate a key or extend the
window; resource limits still apply. Exact TTL, retry and discovery schemas are
not finalized by approval of the convenience flag.

### Default enrollment

Without `--insecure`, root initiates enrollment on the admin socket for a fixed
user ID, creating a
short-lived random ticket. Browser completion cannot choose the user, grant
actions, or become an administrator. New users start without action grants.
Adding a credential to an existing user gives access to that user's existing
grants after activation; root must see that consequence before approval.

Propose two local steps: initiate, then approve a verified pending credential.
The browser exchanges its ticket for one registration ceremony. Registration
verification creates an inactive candidate; root approves that exact candidate
ID and public-key fingerprint via the admin socket before it becomes usable.
The fingerprint is derived by an established hashing library from a defined
public-key representation, not from a browser-chosen display label. Ticket and
pending candidate expire on a daemon-enforced deadline. Consumption, global
credential-ID uniqueness and activation must be transactional.

Important limitation: the relay sees enrollment tickets and can race or replace
the browser registration. Local approval prevents automatic activation but does
not prove that a displayed candidate belongs to the intended person. Root must
approve only an independently verified enrollment, for example one performed
through a trusted local enrollment client/channel. Comparing two values both
delivered by the compromised UI is not independent verification. The precise
trusted enrollment UX/channel is a review blocker, not solved by a fingerprint.
The insecure option explicitly accepts that race; it must never be described
as relay-compromise-resistant enrollment.

Recovery uses the same locally authorized process. It does not grant the new
credential access to downstream key wrappers automatically. Lost passkeys must
not remove existing LUKS recovery options. Remote credential self-enrollment and
remote grant management are deferred.

## Lifetime, concurrency and persistence

Proposed starting limits, subject to review and target-device measurement:

| Resource | Bound |
| --- | --- |
| Authentication/registration ceremony | 120 seconds, monotonic |
| Enrollment ticket and approval window | 10 minutes total from local initiation |
| Pending web ceremonies | 32 total, 2 per user |
| Local enrollment opportunities/candidates | 4 total, independent capacity |
| Credentials offered per user | 16 |
| Concurrent cryptographic verification jobs | 2, no unbounded queue |

Use a cryptographic OS random source for opaque IDs/tickets (proposed 32 bytes).
Keep tickets out of argv, URLs, logs and persistent storage. Explicit CLI display
is necessary for transfer, but not routine logging. Store only ticket verifiers
where practical. Release entries on success, failure, cancellation and expiry.
Restart invalidates all transient ceremony/ticket state. No persisted verifier
state or automatic replay of a previously admitted privileged operation.

Cryptographic verification is synchronous CPU work: keep it off the Tokio I/O
thread with bounded worker admission. A timeout does not interrupt a running
blocking task; hold its capacity permit until it actually completes. Recheck
expiry and policy after verification before admitting an operation.

Persist users, active public credentials, grants and verification metadata in a
root-controlled transactional store. Schema, migration, filesystem validation,
durability and revocation ordering remain shared prerequisites with #3/#15.
Never acknowledge enrollment/metadata updates before required durable writes.

## Wire contract and secret-dependent actions

Do not change v1 status framing while this draft is under review. New operation
names, strict field schemas, extensions and bounds need a separate concrete
wire table before coding. A candidate overall cap is 64 KiB with tighter limits
for each raw field; fixture measurements must justify final numbers. Do not
silently enlarge the current 4 KiB cap or accept an arbitrary JSON object.

Carry browser `clientDataJSON` as bounded original bytes: verification uses the
authenticator's signed representation, not JSON re-serialized by the relay.
Distinguish strict Wudo envelope validation from standards-defined WebAuthn
extension handling. Decide supported extension outputs and bound library
parsing depth/allocations in the suitability spike; reject unreviewed inputs.
Prohibit PRF output/key material in daemon-bound plaintext messages.

For secret-dependent actions, bind the intended secret ID, wrapper credential,
secret revision and exact transport session into daemon-held operation state.
How the encrypted envelope authenticates that binding is #13, not custom
cryptography introduced here. A valid assertion alone cannot accept an
unbound ciphertext. If a verified unlocked prerequisite disappears, fail and
restart the operation rather than silently requesting a key under an old plan.
No-secret paths still need current authentication and action authorization.
Execution/retry/crash semantics remain #16; this draft does not promise exactly
once execution after an ambiguous disconnect.

## Required negative and integration tests

- Wrong signature, RP ID, origin/port, challenge, ceremony type, UP/UV flags,
  credential ownership, user handle where present, and revoked credential.
- Expired, duplicate, concurrent, restarted and failed-then-retried ceremonies;
  finish submitted with a different action/user or configuration revision.
- Revocation/grant changes during verification; counter races/regressions;
  persistence failure prevents activation or action admission.
- Registration ID already assigned to another user; ticket reuse/expiry/race;
  inactive candidate cannot authenticate; wrong root approval cannot activate it.
- Default enrollment: a substituted key cannot activate automatically; verify
  the chosen trusted enrollment procedure catches substitution.
- Insecure enrollment: only root can open the window or select its target;
  absent/expired/cancelled windows reject registration; invalid WebAuthn fails;
  concurrent valid candidates yield exactly one activation; the window never
  grants additional actions or wrappers and cannot be renewed by web requests.
- Full ceremony/worker capacity, bounded parsing, large/nested extension data,
  disconnects, deadlines and canary data absent from diagnostics.
- Real target browser/authenticator registration, authentication and PRF matrix;
  unsupported PRF blocks secret use without blocking unrelated no-secret actions.

## Review and implementation sequence

Origin/RP installation policy, one verification per action and the insecure
enrollment opt-in are accepted. Next review detailed UV policy and default
enrollment authority.
Then resolve trusted enrollment UX, persistent state/revocation ordering and
the exact bounded wire schemas. Validate library behavior and dependencies in
an isolated test harness. Only after explicit review add daemon operations.

Rejected directions: relay-issued authentication grants, client-held verifier
state, first-browser administration, hardware attestation as a default, and
generic reusable action grants. They add trust or scope contrary to Wudo's
purpose. Automatic activation is allowed only through the explicit root-initiated
`--insecure` exception, accepting relay-driven enrollment takeover during that
window. Discoverable login may improve UX later; account-first keeps the
initial principal/credential binding explicit.
