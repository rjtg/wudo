# Trusted action configuration and user grants

Status: **approved by the maintainer and implemented locally**. Tracking:
[#23](https://github.com/rjtg/wudo/issues/23), prerequisite to action
authentication under #12/#15/#16 and roadmap #20.

Browser enrollment is published in `3a1242b`, and its container E2E passed.
The next usable action ceremony needs a trusted action catalog and durable user
grants. The existing wire contract reserves action.begin/action.finish until
execution admission is specified; it forbids a mock action success endpoint.
This slice establishes configuration and grants without enabling those endpoints.

## Operator workflow

Root installs the existing action TOML schema at `/etc/wudo/actions.toml` and
restarts wudod. The daemon loads and validates it once at startup. There is no
live reload, browser-supplied configuration, new file-writing CLI primitive,
or change to `wudo config validate --file`.

Local commands:

```text
sudo wudo action list
sudo wudo grant alice paperless.start
sudo wudo revoke alice paperless.start
sudo wudo grant list alice
```

Action listing shows ID, description and current revision. Grant listing shows
only the named user's active grants, with action ID and revision. Grant creation
resolves an existing user and configured action inside the daemon and binds to
that action's current revision. The caller cannot select an older revision.
Repeated grant/revoke is idempotent; an unknown user/action fails closed. New
users and newly enrolled credentials do not create grants. Credentials inherit
their owner's grants but still require independent active status and verification.

All commands are admin-socket-only. Four strictly typed v2 operations are needed:
action.list, grant.create, grant.revoke and grant.list. They return bounded
pages (16 rows, explicit action-ID cursor) or a typed acknowledgement. No paths,
SQL, executable names, argv or configuration documents enter these messages.
Detailed codec fields and contextual checks are part of this reviewed slice's
implementation, following the existing pagination and admin-only conventions.

## Grant binding and configuration changes

A grant authorizes one exact configured capability, not just its reusable name.
Persist a daemon-generated random 32-byte revision with each action's canonical
definition. Compare typed definitions, not raw TOML text. Include every action
field (including description, confirmation and limits) and any referenced LUKS
resource definition. Use an explicitly versioned, deterministic encoding with
lexicographically sorted object keys and no TOML map-order dependence. Record
format 1 is compact JSON `{ "format": 1, "config": ... }`, containing a validated
schema-1 document with exactly one action and only its referenced resource.
Records are bounded to 4096 bytes and must match exact reserialization on read.
This is private comparison data, not an IPC encoding, cryptographic signature
or executable input.

On startup reconciliation, in one SQLite transaction:

- Identical action definition: preserve its revision and grants.
- New action: generate a new revision; start with no grants.
- Changed action or referenced resource: generate a new revision and delete
  grants for that action. Root must explicitly grant it again.
- Removed action: delete its catalog entry and grants. Reintroducing the same
  name later starts without grants, even if its definition matches an older one.
- Unrelated actions and formatting/comment changes preserve grants.

Example: changing paperless.start from paperless.service to another unit removes
Alice's grant for paperless.start. Changing an unrelated action does not. Even a
description-only change requires regranting in this conservative initial policy.
Changes to systemd unit contents outside Wudo remain trusted root administration;
the action revision binds the configured unit name, not the unit's entire host
dependency graph. Future execution must validate its own privileged targets.

Reconciliation happens before action/grant administration is admitted. No stale
catalog is used after invalid configuration or a failed transaction. Restart
discards transient ceremonies. Future action.finish must recheck the current
revision, grant and active credential at admission, after cryptographic work;
grant revocation during verification must prevent admission.

## Filesystem and missing-configuration policy

Fixed path `/etc/wudo/actions.toml`: root-owned regular file, mode 0600
or 0644, single link, no access ACL, no symlink. `/etc/wudo` must be root:root
0755 without access/default ACLs. Open directories and final file through retained
descriptors with no-follow checks; check trusted root-owned, non-writable
ancestors. Bound reads to 256 KiB plus one byte, using nonblocking/no-follow
opening before file-type validation. Reject changing inode/size/metadata during
the read. Root is trusted; publish replacements atomically rather than editing
the live file in place. Do not reuse the unprivileged validator's weaker path
policy for this loader.

If `/etc/wudo` or actions.toml is absent, treat the catalog as empty, allowing
enrollment-only installations. Reconciliation removes all previous action grants
in that case; restoring the file requires regranting. Any other access or
validation error fails daemon startup rather than silently using an empty or
previous catalog. This distinction must be tested and visible in fixed startup
diagnostics, without printing raw configuration.

## Persistence, recovery and bounds

Use explicit schema v4 via `wudo upgrade`; no automatic database migration.
Persist at most 128 action definitions and at most 128 grants per user (8192
total), under the existing database size ceiling. Reaching the physical ceiling
may fail earlier; it must never produce a partial catalog/grant update.
Foreign keys bind grants to immutable users and current catalog revisions.
Validate stored canonical definitions/revisions/grants on open, with exact schema
and existing filesystem checks. Old-schema maintenance permits upgrade, not
action/grant operations. After upgrade, reconcile the startup snapshot before
admitting those operations.

`wudo init --reset` clears users, credentials and grants, then reconciles the
already loaded root configuration into the fresh installation with no grants.
It never deletes external action TOML, modifies systemd units or touches LUKS.
Storage errors poison the store as today; no success response precedes commit.
Lost grant/revoke replies are resolved through inspection/idempotent retry.

## Validation and next boundary

Test trusted file ownership, modes, ACLs, symlinks, FIFO/device inputs, read size,
missing versus malformed configuration and partial setup. Test revision/grant
preservation for identical definitions and unrelated edits; invalidation for
target, prerequisite/resource, display and policy changes; remove/reintroduce;
restart persistence; reset; migration rollback; transaction failure; grant
capacity/pagination; unknown users/actions; and rejection on the web socket.

No WebAuthn action success, operation receipt, systemd execution, LUKS probing,
PRF or secret transport is added by this prerequisite slice. The subsequent
action ceremony implementation needs durable credential-metadata updates and a
reviewed execution/admission/outcome contract. It must not claim an action ran
merely because an assertion verified.

## Installation and recovery

Create `/etc/wudo` as root:root mode 0755, install a reviewed schema-1 action
file as root:root mode 0644 (or 0600), and restart the daemon. The
[Paperless example](../examples/paperless.actions.toml) needs local UUID/unit
values before use. The offline validator checks syntax, not production path trust.
For an existing installation, run `sudo wudo upgrade` before action/grant commands;
new `wudo init` creates schema 4. Use `sudo wudo action list` to inspect the loaded
snapshot and explicitly grant each intended user/action pair.

Edits take effect only after restart. An invalid or untrusted file prevents
startup; correct its contents/ownership/permissions and restart. A missing file
loads an empty catalog and **deletes existing action grants**. Restoring it
requires explicit regranting. Inspect grants after an uncertain command result.
Do not reset the installation merely to update its action configuration.

## Administrative wire schemas

All four operations use the existing strict v2 CBOR envelope on `admin.sock`.
Optional fields are omitted, never null. `user_id` is a UUIDv4 bstr(16),
`action_id` and cursors use the existing Name grammar (1–64 ASCII bytes).
An action entry is `{action_id, description, revision}`; description is 1–256
UTF-8 bytes, nonblank with no controls, and revision is bstr(32).

| Operation | Request body | Successful response body | Request / response cap |
| --- | --- | --- | --- |
| `action.list` | `{?after}` | `{actions: [entry...], ?next_after}` | 4096 / 8192 |
| `grant.list` | `{user_id, ?after}` | `{user_id, actions: [entry...], ?next_after}` | 4096 / 8192 |
| `grant.create` | `{user_id, action_id}` | `{user_id, action_id, revision, granted: true}` | 4096 / 4096 |
| `grant.revoke` | `{user_id, action_id}` | `{user_id, action_id, revision, granted: false}` | 4096 / 4096 |

Pages contain at most 16 entries, strictly ordered by action ID after the supplied
exclusive cursor. `next_after` is present only when another row exists, and must
match the last entry of a full page. Grant responses must echo the requested
owner; mutations also echo the action and expected boolean. Empty pages are valid.
Unknown users/actions return Unavailable, including revocation of an unknown
action; revocation of an absent grant for an existing user/action succeeds.
Clients cannot send revisions to select an older capability. Web endpoint
requests are rejected before reaching storage. Existing frame, collection,
unknown-field and duplicate-field rules remain in force.

## Review and validation

The maintainer explicitly approved this contract before implementation. Tests
cover canonical comparison, schema upgrade preserving users/origin, transactional
rollback, grant pagination/capacity, restart/reset and admin-only IPC, plus
missing/unsafe/oversized/malformed configuration, symlinks, hard links, FIFO and
ACL rejection. The expanded privileged smoke harness exercises production paths
and the CLI in a private namespace with temporary `/etc`, `/run` and `/var/lib`.
All 109 workspace tests, formatting, workspace and WASM-target Clippy pass.
The maintainer confirmed that the expanded privileged smoke test passed. Action execution and physical-device testing remain
outside this slice.
