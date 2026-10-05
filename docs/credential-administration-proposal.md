# Local user listing, credential inspection and revocation

Status: accepted and implemented locally, including user listing requested by
the maintainer. Tracks #21, #3, #12, #15
and roadmap #20. Builds on the accepted durable credential and enrollment
contracts. SECURITY.md requires review before adding daemon IPC operations.

## Scope and commands

Expose the existing stored credential identities and terminal revocation through
the root-only administrative socket. No schema migration or dependency is needed.

```text
sudo wudo user list
sudo wudo user list --after alice
sudo wudo credential list alice
sudo wudo credential list alice --after CREDENTIAL_ID
sudo wudo credential show alice CREDENTIAL_ID
sudo wudo credential revoke alice CREDENTIAL_ID
```

User listing returns names, display labels and UUIDs, including users with no
credentials. Sort by name using bytewise ordering and return at most 16 users
per page, with an explicit continuation instruction. `--after NAME` is an
exclusive name bound, validated with the existing Name type; it need not name
an existing user. Display labels use the same terminal escaping as `user show`.
An initialized store with no users returns an empty list; missing or unhealthy
storage remains an error. No credential counts or authorization claims are
implied by listing a user.

`CREDENTIAL_ID` is the full credential ID as lowercase hexadecimal, 2–2046
characters with even length. It is public identification data, not a ticket or
secret. Reject prefixes, fingerprints, malformed hex and excess arguments before
IPC. Commands first resolve the existing user name to its UUID; subsequent
requests bind to that UUID, so a reset/recreated name cannot redirect a queued
mutation to a new user.

Listing includes active and revoked credentials, at most 16 per invocation.
Print each full ID and state, the owner's UUID, and an explicit continuation
instruction when another page exists. Do not silently truncate or automatically
issue an unbounded sequence of requests. Show also prints the existing
SHA-256-of-credential-ID fingerprint used during enrollment. A fingerprint
identifies a credential; it does not prove who owns the authenticator.

Revocation takes the exact full ID and user, without an additional interactive
prompt. Successful output confirms that this credential is revoked and warns
that this does not rotate downstream secrets. Revoking the user's last active
credential is allowed: local root remains the recovery authority. No bulk
revocation, deletion, reactivation, user mutation, grants or wrapper management
in this slice.

## CBOR v2 contract

Use the existing strict envelopes and types. Each new operation is admin-only;
the web endpoint rejects it before worker dispatch. The CLI retains root-daemon
peer verification. v1 status and all existing v2 messages remain unchanged.

| Operation | Request body | Successful response body |
| --- | --- | --- |
| `user.list` | `{after?:Name}` | `{users:[{user_id:UserId,name:Name,label:Label}], next_after?:Name}` |
| `credential.list` | `{user_id:UserId, after?:CredentialId}` | `{user_id:UserId, credentials:[{credential_id:CredentialId,state:CredentialState}], next_after?:CredentialId}` |
| `credential.inspect` | `{user_id:UserId, credential_id:CredentialId}` | `{user_id:UserId, credential_id:CredentialId,state:CredentialState,fingerprint:Fingerprint}` |
| `credential.revoke` | `{user_id:UserId, credential_id:CredentialId}` | `{user_id:UserId, credential_id:CredentialId,state:"revoked"}` |

`CredentialId` is a byte string of length 1–1023; `CredentialState` is exactly
`"active"` or `"revoked"`. No verifier record, public-key serialization, ticket,
wrapper or downstream secret is returned. The daemon computes the 32-byte
fingerprint from the full ID using its existing OpenSSL SHA-256 implementation,
exactly as during enrollment inspection.

Requests and single-record responses retain the 4096-byte cap. User-list
responses have an 8192-byte cap: 16 maximum-size names/labels/UUIDs plus envelope
and cursor fit within it. User pages contain 0–16 entries, strictly ordered by
name, with unique UUIDs and names; every name must exceed the request cursor.
If present, `next_after` equals the last returned name and the page contains 16
entries. Read at most 17 rows to determine continuation. These limits preserve
the existing outer CBOR array/item bounds. User listing uses the same
current-state pagination semantics as credential listing below.

Credential-list responses
have a 32768-byte cap, below the existing 65536-byte transport cap. Sixteen
maximum-size IDs with states, UUID and continuation fit comfortably; implement
a maximum-size codec test. Lists contain 0–16 entries, ordered by the raw ID's
unsigned bytewise lexicographic order, with no duplicates. If present,
`next_after` equals the last returned ID and the page has exactly 16 entries.
Each entry must be strictly greater than the request cursor. Contextual decoding
also checks the owner UUID and, for single-record replies, the requested ID.
Unknown fields, enum values, duplicate fields and invalid response correlations
are protocol errors.

The store reads at most 17 rows to determine whether another page exists and
returns 16. An optional cursor is an exclusive ordering bound, not an opaque
session or permission token; it need not name an existing row. Pagination is
a sequence of current-state reads, not a snapshot across requests. Concurrent
enrollment can add earlier IDs; restart listing to refresh. Revocations remain
visible because records are retained. An existing user with no credentials gets
an empty list; an unknown user or credential/owner mismatch gets `unavailable`.

## State changes and failure behavior

Reuse the single storage owner, bounded four-job queue, five-second exchange
deadline, fixed database path and existing filesystem validation. Missing,
unhealthy or upgrade-required storage fails closed. Inspection/revocation do
not require a configured origin, allowing root to inspect historical credentials
after an explicit schema upgrade. They never assign those credentials an origin.

Revocation checks user ownership and updates the selected row in one IMMEDIATE
transaction. A matching already-revoked record also returns `revoked`; an absent
record or wrong owner does not count as success. Acknowledgment follows commit.
Keep the record and its global ID reservation permanently until an explicit
installation reset. It cannot be reactivated, reassigned or enrolled again.
Other credentials and users are unchanged. Active capacity is freed; the total
record count is not. Storage failure poisons the worker under existing rules.

The CLI never automatically retries a mutation after an uncertain response.
Use `credential show` to resolve a lost reply; an explicit repeated revocation
is safe under the above semantics. Queued work is discarded on timeout or
shutdown before execution; an already-started transaction can finish after its
reply is lost, as with existing administrative writes.

Revocation does not cancel unrelated enrollment opportunities or revoke other
credentials. Existing activation rechecks global ID uniqueness, including
revoked records, so pending verification cannot reactivate this ID. A distinct
credential in a separately root-authorized enrollment window remains eligible;
administrators can cancel that window explicitly. Tests must cover this boundary.

Action authentication/execution is not enabled today. A later action slice must
recheck current revocation at admission; a cached Passkey or completed signature
verification is not sufficient. This slice does not promise to cancel actions
that have already started. Revocation cannot revoke a copied downstream key;
that still requires secret rotation. Future wrappers must implement credential
revocation cleanup before they are enabled.

## Acceptance tests

- Codec roundtrips and maximum-size list page; empty list; unknown fields/states,
  malformed/oversized IDs, duplicate/unsorted IDs, invalid cursors in responses,
  mismatched owner/ID and wrong-endpoint rejection for all four operations.
- User listing: empty store, users without credentials, maximum-size fields,
  all 64 users across pages, stable name ordering and continuation, duplicate
  names/UUIDs and wrong-endpoint denial; escape labels safely in CLI output.
- Storage pages spanning more than 16 retained records, deterministic ordering,
  terminal page, empty user, missing user and inspection of active/revoked state.
- Genuine verified credentials: revoke exactly one of two, wrong-owner denial,
  absent versus already-revoked behavior, authentication lookup refusal,
  permanent ID reservation, restart persistence and transaction rollback.
- Socket roundtrips for list/show/revoke; denied web requests cause no mutation;
  reset/recreated owner cannot receive a stale request; pending enrollment cannot
  reactivate a revoked ID; different credentials remain usable/enrollable.
- CLI bounded parsing and category-only diagnostics; no raw verifier records or
  secret-like rejected values in output; owner/ID/state and pagination displayed
  unambiguously; uncertain outcomes direct the operator to inspection.
- LSP diagnostics, cargo fmt, Clippy with warnings denied and relevant tests.
  Extend the isolated smoke harness for empty-list and missing-target failures;
  actual registered-credential revocation is covered by signed socket fixtures
  until browser enrollment is available.

## Accepted scope

The maintainer accepted targeted terminal revocation, including revoking the
last credential and keeping enrollment cancellation separate, then requested
user listing in the same slice. Implement these four root-only operations with
bounded pagination without expanding into browser UI or action execution.

## Implementation and validation

Implemented in the strict v2 codec, bounded storage worker and CLI; no migration
or dependency changes. The store selects only public IDs/state and user display
fields for these operations. User and credential queries read at most 17 rows.
The CLI validates input before IPC, checks root peer identity and operation reply
caps before allocating the body, and does not retry writes automatically.

Tests cover all 64 users across pages, maximum-size encoded pages, reply
correlation/order/cursor rejection, wrong endpoint and wrong owner, repeated
revocation, an injected rollback failure, restart inspection, late verified
results/candidate approval encountering a retained revoked ID, an independent
enrollment remaining usable, reset/recreated users, and CLI input/output and
large-reply bounds. Real signed enrollment fixtures exercise the socket path.

The isolated deployment smoke harness now also checks user listing, empty
credential listing and missing-target inspection/revocation failures. The
maintainer ran the expanded harness and confirmed that all checks pass. Browser registration, actual device/ARM testing, action admission
and downstream secret rotation remain separate work.
