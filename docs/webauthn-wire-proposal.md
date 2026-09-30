# WebAuthn IPC message contract

Status: **codec contract accepted and implemented behind the `v2` feature; runtime integration remains gated**.
Tracking: #12, with persistence/configuration prerequisites in #3/#15 and
execution/secret-transport prerequisites in #16/#13.

The [ceremony policy](webauthn-proposal.md) records accepted decisions. This
document records their accepted wire representation and operational requirements.
The codec does not implement ceremony state transitions or authorize runtime integration.

## Scope and versioning

Retain the four-byte big-endian payload length, CBOR only, one exchange per
connection, request write-half-close, response EOF, kernel peer checks and
separate endpoint connection budgets. A browser ceremony spans multiple short
IPC connections; no socket is held open while the user operates a passkey.

Accepted: keep protocol v1 status exactly as implemented, including its 4096-byte
cap and absence of a `body` field. Introduce v2 with a `body` map for all requests
and successful responses, including status. A v2 client uses v2 status; operations
are not permanently tied to the version in which they first appeared. The version
selects the whole protocol contract, not the application release or operation age.

```text
v1 request: {"version":1,"operation":"status"}
v2 request: {"version":2,"operation":"status","body":{}}
v2 response: {"version":2,"result":"ok","body":{"status":"ready"}}
```

Supporting v1 preserves the existing client contract. Do not replace v1 in place
with the new envelope. The opt-in `wudo-protocol/v2` codec implements the v2
schemas. Runtime handlers and transport dispatch remain v1 only.
No JSON fallback, encoding selector,
compression or automatic downgrade of a failed v2 operation to v1.

Accepted future transport admission cap: 65,536 payload bytes. Because version
is inside the payload, a server cannot apply a version-specific cap from the
length prefix alone. It first admits at most 65,536 bytes from an authorized
peer, then dispatches a strictly parsed envelope and applies the v1 4096-byte
or v2 operation-specific cap. This is an explicit increase in pre-dispatch
memory exposure, not a claim that v1 large frames are accepted. Allocate only
after length and peer checks; retain the existing four admitted connections per
endpoint. An old server closes oversized frames and rejects unsupported v2.

Unknown/malformed versions never cause fallback or allocation beyond the
global cap. Do not invoke a version's schema decoder or mutate state until the
envelope version is valid for that schema. Unsupported-version responses use
the existing v1 error form when no supported envelope can be selected; v2
clients treat it as a terminal incompatibility. Malformed envelopes close with
no response. Valid v2 envelopes get the bounded v2 errors described below.

## Envelope and decoding rules

Every v2 request has exactly these three keys:

```text
{"version": 2, "operation": "enrollment.open", "body": {...}}
```

Every successful v2 response has exactly three keys:

```text
{"version": 2, "result": "ok", "body": {...}}
```

Every v2 error has exactly three keys and no `body`:

```text
{"version": 2, "result": "error", "code": "unavailable"}
```

The outstanding request determines the response body type; there is no second
operation selector or multiplexing ID. `body` is always a definite CBOR map.
Map order is irrelevant. All fields in the tables are required unless explicitly marked optional.
An absent optional field is omitted, never encoded as null. Empty maps/arrays
are permitted only where the specific schema permits them.

Reject duplicate or unknown keys at every Wudo schema level, wrong types,
trailing items, invalid UTF-8, tags, indefinite lengths and floats. CBOR booleans
are accepted only for declared boolean fields. Negative integers are accepted
only in the explicitly allowed COSE algorithm list. Emit shortest encodings;
accept legal non-shortest encodings, without weakening duplicate detection.

General parser ceilings: map keys <=32 bytes; <=16 pairs in any map; <=16 array
elements; nesting <=8 containers including the root; <=512 decoded items total,
counting map keys, values and containers. Apply smaller field bounds below
before allocation/iteration. Do not construct generic unbounded CBOR trees or
recursively skip unknown values. Parse borrowed bytes/strings where practical.
For order-independent envelope dispatch, a bounded structural scanner may
locate the body's byte span using a strictly depth-limited call stack and the above item
budget. It must not allocate a generic tree or use an unbounded library skip.
Only the selected operation decoder interprets that span semantically. Opaque
WebAuthn byte strings have separate inner-parser constraints below.

## Common field types

| Type | Exact contract |
| --- | --- |
| `UserId` | 16-byte CBOR byte string; daemon-generated random UUIDv4; immutable and never reused |
| `Handle` | 32-byte CBOR byte string; daemon-generated OS-random value; typed internally by purpose |
| `Ticket` | 32 random bytes; bearer enrollment capability; not a user credential |
| `CredentialId` | 1..1023 bytes; authenticator-generated opaque identifier; global uniqueness |
| `Name` | 1..64 ASCII bytes, existing action-ID grammar `[a-z][a-z0-9]*([._-][a-z0-9]+)*` |
| `Label` | 1..128 UTF-8 bytes, no Unicode control characters; display only, escape on rendering |
| `ActionId` | Existing validated action ID, same grammar as `Name` |
| `RemainingMs` | Unsigned integer 1..600000; informational remaining lifetime, never client authority |
| `Fingerprint` | 32 bytes: SHA-256 of raw `CredentialId`; display lowercase hexadecimal locally |

An opportunity ID, candidate ID, ceremony ID and operation receipt all use the
`Handle` representation but are different namespaces. Never accept one in place
of another. IDs are opaque references, not proof of authorization. Ticket
comparison and storage use a reviewed library construction; never log tickets.
Candidate fingerprints identify a credential ID, not a person, device model or
verified public-key owner. This replaces the earlier unspecified public-key
fingerprint representation; candidate approval is bound to the stored record.

## Operations and endpoint policy

`A` means admin socket with UID 0; `W` means web socket with the configured UID.
An operation arriving at the wrong endpoint returns `not-permitted` before any
state lookup or mutation. Root on the web socket is still rejected at transport
admission. Maximum request sizes include the entire CBOR envelope.

| Operation | Endpoint | Body | Success body | Max request |
| --- | --- | --- | --- | --- |
| `status` | A, W | `{}` | `{status: "ready"}` | 4096 |
| `user.create` | A | `{name: Name, label: Label}` | `{user_id: UserId}` | 4096 |
| `enrollment.open` | A | `{user_id: UserId, mode: "confirm" / "insecure"}` | Open result below | 4096 |
| `enrollment.inspect` | A | `{enrollment_id: Handle}` | Inspection result below | 4096 |
| `enrollment.cancel` | A | `{enrollment_id: Handle}` | `{state: "cancelled"}` | 4096 |
| `enrollment.approve` | A | `{enrollment_id: Handle, candidate_id: Handle}` | `{state: "active", credential_id: CredentialId}` | 4096 |
| `registration.begin` | W | `{ticket: Ticket}` | Begin result below | 4096 |
| `registration.begin_insecure` | W | `{}` | Begin result below | 4096 |
| `registration.finish` | W | Registration finish below | Finish result below | 40960 |
| `action.begin` | W | `{user_name: Name, action_id: ActionId}` | Action begin result below | 4096 |
| `action.finish` | W | Assertion finish below | `{state: "accepted", operation_id: Handle}` | 12288 |

All response frames are <=65536; only begin responses may exceed 4096.
The first runtime enrollment slice may enable only the user/enrollment/
registration rows plus status. `action.begin`/`action.finish` remain reserved
until their execution and persistent authorization dependencies are implemented
and reviewed. Reserved operations return `unsupported-operation`, not fake
success. There is no generic `authenticate` returning a reusable session/grant.

`user.create` creates a persistent principal with no credentials or grants.
Name must be globally unique and stable in this slice; collision returns
`conflict`. No remote creation, implicit creation during registration or
first-user administrator behavior. Root must have the returned user ID to open
enrollment. Initial user listing/rename/delete and grant/revoke schemas are
separate administrative work, not implicitly enabled here.

`enrollment.open` requires an existing active user and available credential
capacity. It never changes grants. The mode is fixed in daemon state; later web
messages cannot set or upgrade it. `confirm` returns exactly
`{enrollment_id, remaining_ms, ticket}`; `insecure` returns exactly
`{enrollment_id, remaining_ms}`. Initial `remaining_ms` is 600000.
Tickets are displayed only for explicit transfer; not argv, query strings or logs.

Propose one opportunity per user and at most four total; at most one insecure
opportunity globally, so an empty insecure-begin request has an unambiguous
target. No endpoint lists insecure opportunities or lets the browser select a
target. Cancellation never removes an already active credential.

### Registration begin and browser options

Both begin operations return exactly:

```text
{ceremony_id: Handle, remaining_ms: 1..120000, options: CreationOptions}
```

The target user and mode come from the opportunity. `registration.begin`
requires a matching unexpired ticket in confirm mode. The ticket remains valid
for retries inside the same opportunity, but is not returned again. Insecure
begin uses the sole open insecure opportunity. Proposal: allow one pending or
verifying registration ceremony per opportunity; a concurrent begin is `busy`.
This bounds races without claiming the first visitor is the intended person.

`CreationOptions` has exactly:

| Field | Value/bound |
| --- | --- |
| `rp` | `{id: text 1..253, name: text 1..128}` from trusted configuration |
| `user` | `{id: UserId, name: Name, display_name: Label}` from stored user |
| `challenge` | 32 random bytes generated by the verifier |
| `timeout_ms` | Integer 1..120000, <= remaining opportunity lifetime |
| `algorithms` | 1..2 distinct signed integers from `-7, -257`; preserve verifier-offered order |
| `exclude_credentials` | 0..16 distinct `CredentialId` byte strings |
| `user_verification` | Exactly `"required"` |
| `resident_key` | Exactly `"discouraged"`; discovery is not required by this slice |
| `attestation` | Exactly `"none"` |
| `extensions` | `{cred_protect: 3, enforce_protect: false, uvm: true, cred_props: true}` |

This is a typed projection of verifier options, not permission to invent
challenges or change the verifier's state. The adapter must verify the selected
library emits the permitted profile and fail closed on unexpected options.
Mapping fixtures must establish challenge length, algorithms, absent versus
discouraged resident-key semantics and extension handling before integration.
Algorithms are bounded to the listed identifiers, but only those actually
offered by the library may be forwarded; this is not an algorithm override.
The inspected 0.5.5 defaults offer ES256 and RS256; adding another algorithm is
outside this profile. The experiment currently exercises ES256 only.

The Rust UI maps bytes to browser buffers, algorithms to `{type:"public-key",
alg:...}`, and excluded IDs to public-key credential descriptors. `display_name`
becomes `displayName`; other option names map to WebAuthn equivalents. Map
`cred_protect` to `credentialProtectionPolicy:"userVerificationRequired"`,
`enforce_protect` to `enforceCredentialProtectionPolicy`, and `cred_props` to
`credProps`. No authenticator attachment or transport hints are required.
The library adapter maps these same typed values back without generic JSON IPC.

### Registration finish and local approval

Exact registration-finish body:

```text
{ceremony_id: Handle, credential_id: CredentialId,
 client_data: bytes(1..4096), attestation_object: bytes(1..32768),
 client_extensions: RegistrationExtensions}
```

`RegistrationExtensions` is a map with only optional `resident_key: bool` and
`cred_protect: integer 1..3`; an empty map is valid. These browser-reported
properties are advisory, not authorization or proof of UV. No HMAC/PRF output,
arbitrary extension bag, plaintext secret, browser-supplied user/mode, public
key replacement or confirmation boolean is permitted.

The UI sends raw `rawId` bytes once, not redundant `id` and `rawId` variants.
The verifier adapter derives the library's base64url `id` and constant
`type="public-key"`; other credential types are rejected at the UI adapter.
Preserve `clientDataJSON` and `attestationObject` byte-for-byte. The verifier
must extract the attested credential ID and verify consistency with the supplied
identifier; adapter tests must confirm this rather than trusting outer metadata.

On success in confirm mode: `{state:"pending-approval"}`. On success in insecure
mode: `{state:"active"}`. Neither response includes a session, ticket, user
directory, grants or secret wrapper. The web UI need not poll root-only state;
the root CLI inspects/approves and the user can subsequently authenticate.

`enrollment.inspect` returns one of these exact variants:

- `{state:"open", user_id, mode, remaining_ms}`
- `{state:"registering", user_id, mode, remaining_ms}`
- `{state:"pending-approval", user_id, mode:"confirm", remaining_ms,
  candidate_id, credential_id, fingerprint}`

No list or unbounded data in the response. The CLI may resolve the known user
locally but must not label the fingerprint as verified device ownership.
The pending candidate is immutable. Approval names both opportunity and
candidate, rechecks their relation, current user status, expiry, uniqueness and
capacity, then durably activates that exact public credential. Insecure mode
does not expose approval as an alternative activation path.

Closed opportunities return `unavailable`. Lost success responses may therefore
be ambiguous; do not silently create another credential or retry activation.
Persistent credential inspection/recovery through a later admin API is a
prerequisite for production rollout, not a reason to retain tickets indefinitely.

### Action ceremony (reserved until execution review)

Resolve `user_name` and `action_id` against current daemon state before issuing
a challenge. Return generic `unavailable` for missing/revoked user, action,
grant or usable credentials. No claim of constant-time enumeration resistance.

Begin result is exactly `{ceremony_id, remaining_ms, options: RequestOptions}`.
`RequestOptions` has exactly `{rp_id: text 1..253, challenge: bytes(32),
timeout_ms: 1..120000, allow_credentials: [1..16 distinct CredentialId],
user_verification:"required"}`. No client extension input in this initial
authentication-only profile. Secret-dependent ceremonies need #13/#14 additions
before use, including PRF input selection and authenticated transport binding.

Exact assertion-finish body:

```text
{ceremony_id: Handle, credential_id: CredentialId,
 client_data: bytes(1..4096), authenticator_data: bytes(37..4096),
 signature: bytes(1..1024), ? user_handle: UserId}
```

`?` indicates the only optional field. If present, user handle must equal the
immutable user ID bound at begin; it never selects the principal. No client
extension outputs are forwarded for this profile. The authenticator flags,
signature, challenge, origin and RP hash are checked by the verifier, with
Wudo's current credential/owner/grant/revision checks around it.

`action.finish` admits only the bound action once all checks and required
metadata persistence succeed. `accepted` is an operation receipt, not proof of
execution success and not a reusable capability. No `execute(receipt)` message
exists. Exact durable admission, outcome retrieval, retry/disconnect and crash
semantics must be resolved in #16 before these rows are enabled. An enrollment
implementation must not add a mock action path to demonstrate authentication.

## Opaque WebAuthn fields are still untrusted

Frame limits do not bound the complexity of embedded JSON/CBOR automatically.
Before library verification, enforce inner bounds with established parsers:
`client_data` JSON <=8 nesting levels, <=64 total members/elements, no duplicate
keys; attestation CBOR <=8 container levels, <=256 items, no duplicate map keys,
tags or indefinite lengths. Fail on lengths exceeding remaining input and
reject trailing documents/items. Apply the same bounded CBOR rules to any authenticator-data extension block,
using the verifier/library's structural facilities rather than custom crypto
parsing. If available APIs cannot enforce these limits, resolve that gap before
runtime integration. These conservative compatibility restrictions
need fixture coverage; do not write a custom cryptographic parser or assume a
Serde default silently enforces them.

The JSON envelope's known fields must have WebAuthn types. Unknown inner JSON
members, including new standards fields, are rejected in this initial strict
profile until reviewed; preserve original bytes after validation for signature
verification. Accepted allowed fields are `type`, `challenge`, `origin`, and
optional `crossOrigin:false`; `topOrigin`, token binding and embedded ceremonies
are unsupported. This strict codec profile requires browser/verifier compatibility fixtures
before runtime integration. Map inner structural failures to `invalid-request`, never echo
input or library errors. Cross-origin behavior still needs dedicated verifier
and adapter tests before enabling a runtime ceremony.

Attestation formats, COSE validation, signature algorithms, RP hash and signed
authenticator extensions remain the verifier's responsibility. The above guards
bound syntax; they do not replace semantic/cryptographic validation. Never log
or Debug-print verifier input/state, even with a malformed-input diagnostic.

## State, time and admission ordering

Use monotonic deadlines. Remaining-time fields are advisory and rounded down;
if less than one millisecond remains, treat the record as expired. A pending
ceremony's deadline is min(begin+120 seconds, opportunity deadline if present).
No browser field or repeated request can renew it.

```text
confirm:  OPEN -> REGISTERING -> PENDING_APPROVAL -> ACTIVE (durable)
insecure: OPEN -> REGISTERING --------------------> ACTIVE (durable)
                    |
                    +-- failed/expired ceremony -> OPEN, if opportunity live
```

Expiry/cancellation from any pre-activation state closes the opportunity and
discards candidates. Activation closes it too. Restart discards all transient
records. An active credential is never revoked merely by later cancelling its
former enrollment opportunity.

For a structurally valid finish at the right endpoint, atomically take its
pending ceremony before verification or worker admission. Missing/expired/taken
IDs are `unavailable`. A failure, including unavailable worker capacity, consumes
that challenge. Malformed frames/envelopes are not used to fish a ceremony ID
out of partially parsed data; they produce no semantic state transition.

Hold the opportunity's REGISTERING slot through verification. Cancellation or
expiry may mark it closed while a worker runs; completion must recheck before
storing/activating anything. Registration failure releases the slot for a new
ceremony if the opportunity remains live. Confirm mode permits only one pending
candidate, so a later browser request cannot replace what root is inspecting.

Proposed capacities: 32 total web ceremonies (pending plus verifying), two per
user; four enrollment opportunities; 16 active credentials per user. Inactive
candidates reserve credential capacity. Two crypto workers globally, no
unbounded waiting queue. Hold worker capacity until the computation finishes,
even after request timeout. Expired pending entries are reclaimed before capacity
checks. Rejections do not evict live records or reset their deadlines.

Durable activation and credential-ID uniqueness must be one transaction. Root
approval races, cancellation and user revocation require a defined serialization
point. A lost response cannot roll back committed state. Active credential state,
inspection recovery and transaction mechanics remain the next persistence
contract; in-memory prototypes must not claim durable enrollment success.

## Errors, examples and validation

V2 codes: `invalid-request`, `unsupported-operation`, `not-permitted`,
`unavailable`, `verification-failed`, `busy`, `conflict`, `internal-error`.
`conflict` is admin-only. Unknown/expired/consumed handles share `unavailable`.
Verification failures share one code regardless of signature/UV/origin reason.
No message text, parser offset, user input, OS error or retry token is returned.
Framing errors, unauthorized kernel peers and transport deadlines close without
a response. Whole-exchange transport timeout remains five seconds.

Order: kernel peer -> frame/global cap -> envelope/version -> operation and
endpoint -> strict body/per-operation cap -> state/capacity -> verification ->
fresh policy/deadline checks -> durable mutation/admission -> bounded reply.
No mutation before complete schema validation. Bad bodies do not qualify for
state-specific errors. Unknown operations never cause semantic body decoding; only the bounded
envelope scan is permitted.

Illustrative diagnostic notation (angle-bracket placeholders are not wire text):

```text
{"version":2,"operation":"enrollment.open",
 "body":{"user_id":<16 bytes>,"mode":"insecure"}}

{"version":2,"result":"ok",
 "body":{"enrollment_id":<32 bytes>,"remaining_ms":600000}}

{"version":2,"operation":"registration.begin_insecure","body":{}}

{"version":2,"operation":"enrollment.approve",
 "body":{"enrollment_id":<32 bytes>,"candidate_id":<32 bytes>}}
```

Required tests: exact/over-limit fields and frames; duplicate/non-shortest keys;
wrong endpoint; client-supplied target/mode/argv/path/grants; extra/missing fields;
deep embedded documents; raw JSON byte preservation; no extension secret leak;
option mapping parity; unknown/expired/replayed IDs; failed verification retries;
cancel/approve/finish/revoke races; one insecure winner; failed durable commits;
capacity reclamation; no sensitive values in errors/logs; v1 unchanged and v2
incompatible-server behavior. Size arithmetic for shortest CBOR encodings gives 38,080 bytes for a
registration-finish request with every field at its bound, and 10,421 bytes for
an assertion-finish request including a user handle. Both fit their operation
caps. Actual maximum-size fixtures, including permitted non-shortest encodings,
need codec tests; field-limit arithmetic is not proof of parser resource bounds.
Maximum-size valid fixtures must fit CPU/memory budgets before implementation.

Implemented codec slice: typed requests/responses, checked CBOR encode/decode,
endpoint restrictions and negative fixtures in `wudo-protocol`, behind its
non-default `v2` feature. Existing daemon/CLI behavior and the v1 cap are unchanged.
Encoding validates constructed values; callers must discard the output buffer
when encoding fails. Data-bearing protocol types deliberately omit `Debug`.

Tests exercise all operation/response shapes, truncation, field injection,
duplicate keys, bounded embedded documents and maximum-field request sizes.
Fixtures are structural, not verified WebAuthn ceremonies. The codec preserves
signed input bytes and performs no authentication or authorization.

Remaining integration gates: durable state and atomic ceremony transitions;
verifier option mapping and browser compatibility; structural limits inside
opaque authenticator-data byte strings (including extension/COSE structures).
The codec bounds client-data JSON and attestation CBOR containers, but does not
parse authenticator-data internals. Close that gap through established library
facilities before enabling handlers, without a handwritten authenticator parser.
