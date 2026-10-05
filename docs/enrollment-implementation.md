# Daemon enrollment implementation

Status: daemon enrollment IPC and local CLI implemented locally. Browser UI is pending.
Tracking: [#12](https://github.com/rjtg/wudo/issues/12),
[roadmap #20](https://github.com/rjtg/wudo/issues/20).

## Implemented boundary

The `wudod` library contains a serialized enrollment state owner and a typed
adapter to the pinned webauthn-rs verifier. It accepts encoded v2 messages,
using the existing codec to enforce endpoint policy and structural bounds
before state mutation. The transport must still authenticate the kernel peer;
an endpoint enum alone does not establish root authority.

Root opens a ten-minute opportunity for an existing user. Confirm mode returns
a random ticket once and retains only its SHA-256 digest, compared through
OpenSSL's constant-time comparison. Insecure mode has one globally unambiguous
opportunity. There are four opportunities maximum and one per user. A pending
opportunity reserves one global credential slot and that user's enrollment slot; durable activation independently
rechecks global/per-user storage capacity and uniqueness.

Begin obtains a genuine verifier challenge and projects the approved option
profile. Unexpected library settings fail closed; absent resident-key preference
with `requireResidentKey=false` maps to discouraged. The original challenge,
user, RP and offered algorithms are preserved. The existing response encoder
checks all projected sizes and field values. No PRF output is accepted.

A structurally valid finish takes its challenge before worker admission. The
owned verification job holds one of two global permits, including after
cancellation. Its result contains the original opportunity and ceremony binding.
Verification checks the actual registration through the established library and
compares the attested credential ID with the wire ID. Original signed bytes are
not rewritten. Existing inner authenticator-data parser deferrals still apply.

The serialized completion step rechecks current opportunity, ceremony and
deadlines. Cancellation, expiry, a newer ceremony or restart prevents activation.
Failed verification releases the opportunity for a fresh challenge while its
original deadline remains live. A verifying slot is retained until completion;
if its job/result is abandoned it remains unavailable until cancellation or
opportunity expiry. A busy worker rejection consumes the challenge and leaves
the live opportunity open for retry.

Confirm mode creates an immutable candidate with a credential-ID fingerprint.
Approval must name that exact opportunity and candidate. Insecure mode performs
durable activation directly. Approval/activation removes the opportunity before
attempting the storage transaction; a failed or uncertain write cannot be
silently retried through the same opportunity. Success is returned only after
commit. Revoked/existing IDs cannot be reused. Cancellation never revokes a
previously activated credential. No grants or wrappers are created.

## Runtime and CLI

`wudod` enables the reviewed root enrollment and web registration operations.
Action begin/finish remain unsupported. The state/storage owner runs on a
separate thread with a four-entry queue. General administration uses nonblocking
admission; enrollment requests await this queue within the existing socket
admission limits and five-second exchange deadline. Cancelled/expired queued
requests are skipped before semantic processing. Finish consumes its challenge
on the state owner before crypto admission; a crypto Busy rejection consumes it.

At most two verifier threads/jobs exist, with no crypto waiting queue. Owned
permits cover verification and completion delivery, including after cancellation,
reset or client timeout. Completion returns through the bounded state queue and
rechecks current binding/deadlines before any candidate or durable mutation.
Cancellation/reset and approval/activation serialize on the same state owner.
Status runs independently on Tokio's I/O thread. Reset retains shared worker
capacity across changes to the stored origin.

Once verification starts, losing the reply does not cancel its completion:
valid insecure enrollment may still commit. A closed opportunity after a lost
reply is ambiguous; never retry activation automatically. Shutdown stops state
admission, discards queued/late results, and joins existing verifier threads;
an already-started database transaction finishes. Bounded input/workers do not
promise a hard wall-clock limit for third-party crypto or blocked kernel I/O.
A worker panic or internal storage failure makes state operations unavailable.

The verifier is constructed solely from settings saved by `wudo init`; no
browser/relay/header chooses the RP or origin. Installation reset invalidates all
transient state. See [installation setup](installation-setup.md).

```text
sudo wudo user create alice --label Alice
sudo wudo enroll alice
sudo wudo enroll inspect ENROLLMENT_ID
sudo wudo enroll approve ENROLLMENT_ID CANDIDATE_ID
sudo wudo enroll cancel ENROLLMENT_ID
# Explicitly accept the first valid registration without candidate approval:
sudo wudo enroll alice --insecure
```

Handles/fingerprints are lowercase hexadecimal. Default opening displays the
one-time ticket for private transfer to the UI; it is never put in argv or a
URL, and cannot be retrieved by inspect. Approval names the exact candidate;
inspection labels the fingerprint as credential identity, not human ownership.
Insecure opening warns about the enrollment race and inherited user permissions;
it neither creates grants nor provisions secret wrappers. The browser must
still complete registration through the web-runtime IPC operations. `wudo-web`
and the Rust/WASM browser UI are not yet implemented, so these commands alone
do not provide a complete browser enrollment experience.

Durable credential inspection/targeted revocation and lost-reply recovery remain
production rollout prerequisites. Real browser/authenticator/ARM validation,
PRF, action authorization and privileged action execution remain separate work.

## Validation

Synthetic tests reconstruct browser options from the actual projected wire
response and sign compliant client data through the upstream software
authenticator. They cover exact approval, durable activation, restart, replay,
wrong endpoint, malformed requests, outer-ID substitution, UV and origin
rejection, cancellation/expiry during verification, ticket and opportunity
bounds, approval expiry, worker capacity and failed durable writes. Software UV
is simulated; these tests do not establish browser or hardware compatibility.

Socket tests exercise signed registration and durable approval, denied web
administration, replay, status during blocked crypto, reset/cancel races,
shutdown dropping late results and completion after a lost reply. Global
credential reservations include revoked records and are released on cancellation.
