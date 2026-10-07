# SQLite identity storage

Status: **SQLite and the isolated user-storage slice accepted; implemented and published**.
Tracking: [#3](https://github.com/rjtg/wudo/issues/3),
[#15](https://github.com/rjtg/wudo/issues/15), and
[ceremony integration #12](https://github.com/rjtg/wudo/issues/12).

## Decision and scope

Use SQLite through `rusqlite`, replacing the proposed custom CBOR snapshot
store. SQLite owns transaction locking, journaling, commit and crash recovery.
The user approved a smaller first slice: explicit database initialization,
schema validation, transactional user creation and lookup, with restart tests.
The earlier snapshot protocol and configuration-wide grant invalidation proposal
are not adopted by this change. Per-action grant binding is now covered by the approved
[action/grant contract](action-grants-proposal.md).

`wudo-store` is a synchronous workspace crate. The approved
[administration slice](user-administration-proposal.md) integrates it through
a dedicated bounded worker off Tokio's I/O thread.
The synchronous API can move to that worker without exposing SQL to clients.

Bundled SQLite gives a reproducible native build without requiring a system
SQLite development package. This introduces C code through `libsqlite3-sys`,
with Rust's safe `rusqlite` API above it; Wudo adds no unsafe code. The dependency
needs updates like the other privileged dependencies before runtime integration.
No ORM, pool, extension loading, SQL scripts from clients or configurable VFS.

## Implemented user contract

- Explicit `initialize(directory)` creates `identity.sqlite3` exclusively.
  Existing files are never overwritten, migrated, repaired or reset.
- `open(directory)` requires an existing database with Wudo application ID
  `0x5755444f`, schema version 4, and the exact expected schema. Unknown versions,
  extra tables/views/triggers and invalid persisted users fail closed.
- The users STRICT table contains a 16-byte UUIDv4 user ID, unique name and label.
  IDs come from the OS random source and are generated inside `create_user`.
  Names follow the v2 grammar (1–64 ASCII bytes); labels are 1–128 UTF-8 bytes
  without control characters. There are at most 64 users.
- `create_user(name, label)` uses bound SQL parameters and an IMMEDIATE
  transaction for uniqueness/capacity checks and insertion. Return success only
  after commit. UUID collisions fail rather than replacing another identity.
- Look up by typed ID or validated name. Absence is distinct from a storage
  failure. No user disable, deletion or rename operation exists.
  Creating a user confers no permissions.
- Errors are fixed categories without source errors, SQL, paths or user values.
  User records and IDs deliberately do not implement Debug.

## SQLite settings and failure behavior

Use rollback journal mode DELETE with `synchronous=EXTRA`; EXTRA also requests
sync of the directory when removing the rollback journal. Check the effective
synchronous and journal settings. Enable defensive mode, disable trusted schema,
keep foreign-key enforcement enabled, and use memory-only temporary storage.
There is no WAL mode in this slice.

Bound lock waiting to 100 ms; serialized callers are the intended integration.
A storage error during user creation makes that Store instance unavailable,
including subsequent reads, until reopened and validated. This conservative
rule also applies to lock timeouts. Duplicate input and capacity rejection do
not poison the store. Lost replies do not undo a committed user; name lookup
allows inspection after reconnect without implying idempotent creation.

The database and existing journal are capped at 4 MiB before open; 4096-byte
pages and a 1024-page ceiling bound database growth. SQLite value and SQL limits
are 64 KiB and 4096 bytes; attached databases are disabled. Opening runs a bounded
`quick_check(1)`, exact schema comparison and validation of at most 65 user rows and 1025 credential rows.
These checks are for trusted local state, not a public database-upload parser.

Missing, corrupt, incompatible and partially initialized files fail closed.
Failed initialization may leave a file requiring explicit local intervention;
never silently delete it or retry by replacing state. Initialization also syncs
the database and containing directory before reporting success.
SQLite handles valid hot-journal recovery; Wudo does not discard or restore
journals itself. Tests of application behavior do not prove power-loss durability
on the Pi; the filesystem and storage must honor SQLite's sync requests.

## Filesystem boundary and integration gate

This library requires a **trusted, stable, absolute private directory** supplied
by its caller. It checks that the directory is not a symlink, is owned by the
process effective UID and has mode 0700. Existing database/journal files must be
regular, single-link files with the same owner and mode 0600. Reject symlinked
leaves, unsafe modes/types and WAL/SHM sidecars. Initialization creates the file
with mode 0600; SQLite opens without CREATE or URI flags, with NOFOLLOW.

This is not the production root path resolver. Ancestor trust, descriptor-based
path resolution and protection against directory replacement are prerequisites
owned by the daemon integration described in the administration contract. Callers must not pass remote-selected
paths or share this directory with other writers. Tests use private temporary
directories as an ordinary user. No environment variable relaxes a root policy:
the daemon enforces root ownership and validates the complete path before
invoking this API.

## Remaining slices

The [local user administration contract](user-administration-proposal.md)
implements initialize/upgrade/create/show, root-only dispatch, production path
checks and a bounded worker lifecycle.

- Enrollment, RP/origin binding and local recovery are implemented. Credential
  metadata updates after authentication remain separate work.
- Pending ceremonies, tickets and candidates remain memory-only and never belong
  in the database; restart invalidates them under the accepted ceremony policy.

## Validation

Tests cover explicit initialization, persistence on reopen, unique IDs/names,
lookup, maximum users and field lengths, bound SQL values, schema/version and
record rejection, unsafe files/sidecars, concurrent duplicate creation, rollback,
and fail-closed lock errors followed by recovery through reopen.
Production ownership/ancestor checks, abrupt process/power failure and ARM tests
remain integration work; the unit tests do not substitute for those checks.

References: [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html),
[SQLite synchronous settings](https://www.sqlite.org/pragma.html#pragma_synchronous),
and [rusqlite](https://docs.rs/rusqlite/0.40.2/rusqlite/).

## Durable credential records (schema v2)

The approved storage slice adds a STRICT credentials table linked to users.
Activation, active lookup for a specified owner, and terminal revocation are
trusted internal APIs only; no new IPC handlers or CLI commands are enabled.
The caller must verify the registration and enforce ceremony/approval binding.
Passing a library `Passkey` alone is not proof of verification.

Credential IDs are globally unique, 1–1023 bytes. Revoked records remain stored
and cannot be reactivated or reassigned. Limits are 16 active credentials per
user and 1024 total records including revoked credentials. These are ceilings,
not guaranteed capacity: the existing 4 MiB database limit still applies.

Record format 1 is the pinned webauthn-rs 0.5.5 public `Passkey` serialized as
JSON, bounded to 16 KiB. Reads require the writer's exact reserialization,
a matching credential ID, and the known format version; unknown or duplicate
fields and incompatible records fail closed. This is a private storage format,
not the IPC encoding. Library upgrades must explicitly assess compatibility and
introduce a record migration when necessary. No private authenticator key or
plaintext downstream secret is stored. The dependency uses OpenSSL; workspace
CI installs its native build prerequisites.

Initialization now creates schema v4 (including settings, actions and grants). Valid v1/v2/v3 stores remain maintenance-only until
explicit `wudo upgrade`, which preserves users/credentials/settings and adds
missing tables transactionally. Historical schemas are validated before migration.
Tests cover a genuine verified credential surviving restart and verifying an
assertion, owner isolation, duplicate IDs, terminal revocation, capacity,
corrupt/incompatible records, and v1-to-v2 preservation.

Authentication must still recheck current credential status at admission.
The internal metadata persistence API below is implemented; daemon ceremony
integration remains a future slice. A previously returned
credential clone does not prove that the credential remains active.

## Installation settings (schema v3)

See [installation setup](installation-setup.md) for the root-only init command,
canonical HTTPS origin validation, singleton storage and the explicit upgrade
path. Upgrade never invents an origin. Existing unbound credentials prevent
configuration; users alone can be preserved while configuring an upgraded store.


## Action catalog and grants (schema v4)

The [approved action/grant contract](action-grants-proposal.md) adds STRICT
`actions` and `grants` tables. Actions store canonical definitions (format 1,
maximum 4096 bytes) and random 32-byte revisions. Grants bind a user to an action
and its current revision through foreign keys. Startup reconciliation is atomic;
changed/removed actions cascade deletion of their grants. At most 128 actions
and 8192 grants (128 per user) fit within the existing 4 MiB physical ceiling.
Opening validates exact schemas, bounded canonical definitions, revision lengths
and all grant references. Reconciliation and mutation failures fail closed.
Reset deletes grants and catalog entries in the identity-reset transaction;
the daemon then reconciles its startup snapshot before returning success.


## Authentication metadata updates (schema v4, no migration)

Implemented internal API for the first slice of #24. `authentication_snapshot`
returns an opaque owner-bound snapshot of one active credential. Its read-only
passkey is the input to the established verifier; the snapshot has no public
constructor, mutable fields, Debug or serialization implementation.

`commit_authentication` consumes that snapshot and accepts the verifier's
`AuthenticationResult`. It uses webauthn-rs `Passkey::update_credential` rather
than replacing client-selected credential data or implementing counter logic.
An IMMEDIATE SQLite transaction rechecks owner, active status and exact canonical
record bytes. Missing/revoked/reassigned credentials or differing current metadata
return Conflict; the caller must discard the result and start a new ceremony,
not retry it against a newer snapshot. This conservatively rejects even a newer
counter result when its verification snapshot is stale.

The update preserves ID, owner, public key, record format and revocation state.
Existing 16 KiB record bounds and canonical serialization apply. Commit precedes
success; SQL/storage failures roll back and poison the Store until validated
reopen. Conflicts and mismatched result IDs do not poison the Store. Backup state
and eligibility changes are applied through the library as well as counters.
Even when the library reports no metadata change, owner/status/snapshot checks
and the transaction are required. The returned boolean means metadata changed,
not authentication or authorization success.

This API is trusted internal persistence, not a cryptographic proof boundary:
AuthenticationResult is a library data type that can be deserialized. Only an
actual successful, purpose-bound, single-use verification may supply it. It must
never be accepted from IPC. Runtime still owns challenge consumption, origin/RP,
UV, expiry, reset generation, current grants/revisions and final admission.
No-change/counterless authentications do not create a record revision; matching
bytes are not replay detection or proof that no intervening ceremony occurred.
Daemon serialization must prevent reset/revocation between final admission and
submission; this storage transaction alone does not authorize a systemd call.

Tests use genuine software-authenticator verification for counter persistence,
stale snapshots across Store connections, result-ID mismatch, reset/revocation,
rollback and reopen. Explicitly synthetic result fixtures cover counterless and
backup-flag storage paths; those fixtures do not claim cryptographic verification.
No daemon handlers, IPC fields, dependencies or database schema change here.
