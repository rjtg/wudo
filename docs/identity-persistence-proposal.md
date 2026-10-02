# SQLite identity storage

Status: **SQLite and the isolated user-storage slice accepted; implemented locally**.
Tracking: [#3](https://github.com/rjtg/wudo/issues/3),
[#15](https://github.com/rjtg/wudo/issues/15), and
[ceremony integration #12](https://github.com/rjtg/wudo/issues/12).

## Decision and scope

Use SQLite through `rusqlite`, replacing the proposed custom CBOR snapshot
store. SQLite owns transaction locking, journaling, commit and crash recovery.
The user approved a smaller first slice: explicit database initialization,
schema validation, transactional user creation and lookup, with restart tests.
The earlier snapshot protocol and configuration-wide grant invalidation proposal
are not adopted by this change. Grant semantics remain a separate review.

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
  `0x5755444f`, schema version 1, and the exact expected schema. Unknown versions,
  extra tables/views/triggers and invalid persisted users fail closed.
- The sole STRICT table contains a 16-byte UUIDv4 user ID, unique name and label.
  IDs come from the OS random source and are generated inside `create_user`.
  Names follow the v2 grammar (1–64 ASCII bytes); labels are 1–128 UTF-8 bytes
  without control characters. There are at most 64 users.
- `create_user(name, label)` uses bound SQL parameters and an IMMEDIATE
  transaction for uniqueness/capacity checks and insertion. Return success only
  after commit. UUID collisions fail rather than replacing another identity.
- Look up by typed ID or validated name. Absence is distinct from a storage
  failure. No credential, grant, disable, deletion or rename operation exists.
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
`quick_check(1)`, exact schema comparison and validation of at most 65 user rows.
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

- Established verifier credential serialization and its size/compatibility tests.
- Credential activation/revocation, grant binding, RP/origin binding, migrations
  and local recovery policy. No earlier proposal for these is implicitly accepted.
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
