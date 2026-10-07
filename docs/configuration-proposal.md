# Action configuration and offline validation proposal

Status: **schema version 1 implemented; trusted startup loading and local grants
implemented under the approved [action/grant contract](action-grants-proposal.md).
Action execution remains unimplemented**.
Tracks [configuration #15](https://github.com/rjtg/wudo/issues/15) and
[action semantics #16](https://github.com/rjtg/wudo/issues/16).

The reviewable example is [paperless.actions.toml](../examples/paperless.actions.toml).
Its UUID is illustrative and its systemd unit must be supplied by the host
administrator. Parsing the example does not make it deployable.

## Agreed boundaries

- Root-owned configuration defines actions, fixed targets, secret definitions
  and limits. Clients choose action IDs, never device paths or unit names.
- Users, credentials, authorization grants, wrappers and lifecycle progress live
  in daemon-managed state. Local administrative CLI operations manage grants.
- An action authorizes its complete configured behavior. Internal prerequisites
  are not separately authorized actions. No recursive action dependencies.
- Every invocation requires daemon-verified authentication and authorization.
- A verified existing mapping needs no PRF operation, secret unwrap or secret
  transport. When unlock is necessary, usable secret material and an eligible
  credential are required. A mapping name alone is not proof of identity.
- Wudo unlocks storage and requests a fixed unit start. Administrator-configured
  systemd units handle mounting and application orchestration.

The owner requested implementation of issue #3 after reviewing the example.
The offline slice adopts the concrete bounds and strict variant rules below.
This records implementation policy, not approval of unresolved runtime behavior.
Authentication, secret transport, state lifecycle and execution remain separate
review gates. No daemon dependencies were added by the offline implementation.

## Scope of this document

Start with an action/resource configuration document containing only
`schema_version`, `resources`, and `actions`. It is not the entire daemon
configuration. WebAuthn RP/origin settings, IPC paths and identities, transport
keys and persistent-state locations require their own reviewed schemas. This
proposal deliberately does not assign defaults to those security settings.

Use one UTF-8 TOML document; no includes, overlays, environment substitution,
path expansion or remote fetching. No keys, passphrases, wrappers, users,
credentials, grants or lifecycle states are accepted in this document.

## Objects and fields

All fields below are required unless explicitly marked optional. No implicit
security-policy defaults. Unknown fields are errors at every nesting level.

| Object | Fields | Meaning |
| --- | --- | --- |
| Root | `schema_version`, `resources`, `actions` | Version integer must be exactly `1`; the other fields are ID-keyed tables. Empty tables are allowed. |
| LUKS resource | `kind`, `luks_uuid`, `mapping_name`, `managed_secret` | Kind exactly `luks2`; defines the container, desired mapping and integration-specific managed key in one place. |
| Managed secret | `id` | Stable secret ID, nested under its owning resource. Definition only; no material, wrappers, keyslot metadata or lifecycle state. Its LUKS key type follows from the resource kind. |
| Action | `description`, `confirmation`, `timeout_seconds`, `output_limit_bytes`, `operation` | Display text, explicit confirmation policy, execution/output bounds, and one typed operation. Optional `prerequisite` is described below. |

`operation` is a strict tagged union:

| `kind` | Required fields besides `kind` | Optional fields | Meaning |
| --- | --- | --- | --- |
| `luks-unlock` | `resource` | None | Ensure this LUKS resource is unlocked; a verified existing mapping is success. |
| `systemd-start` | `unit` | None | Start a fixed unit after satisfying any configured prerequisite. |
| `systemd-stop` | `unit` | None | Stop a fixed unit; does not unmount or close a LUKS mapping. |

There is no generic `command`, `argv`, `environment`, `steps`, `depends_on`, or
client-selected target. Fields from another union variant are rejected.
A plain `systemd-start` needs no resource or secret, supporting root-only actions.

An optional action-level `prerequisite` is a separate strict tagged union. Its
only initial variant is `{ kind = "luks-unlocked", resource = "resource-id" }`.
It means ensure the referenced LUKS resource is unlocked, not just inspect it:
use that resource's managed key if needed, otherwise verify its existing mapping.
The entire behavior is covered by the enclosing action's authorization.

Initially allow this prerequisite only with `systemd-start`; reject it on other
operation variants. There is at most one prerequisite, no prerequisite list,
recursion, action reference or arbitrary sequencing. Unknown prerequisite kinds
and resource-kind mismatches fail closed. Future integrations need separately
reviewed resource, secret lifecycle, operation and prerequisite semantics.

The LUKS integration owns provisioning, keyslot handling, unlock and rotation.
Credential wrapping and authenticated transport are shared infrastructure.
Secret identity remains separate from resource identity for wrapper/lifecycle
binding, but configuration declares their relationship once, through nesting.
Changing either identity or their association requires reviewed state migration;
it must never silently reuse another resource's key or wrappers.

`confirmation = false` would skip an additional application confirmation screen,
not authentication, user verification or authorization. A confirmation screen
cannot prove user intent against malicious UI delivery. Exact ceremony rules
remain in issue #12; the parser must not be mistaken for their implementation.

## Offline lexical rules and limits

These are conservative initial offline limits.
Check the byte limit before parsing, including when input grows while reading.
The TOML 1.0 parser (`toml` 0.8, parse feature only) retains its default
recursion guard (80 in the locked `toml_edit` version), covering nested values
and dotted keys. Do not enable its `unbounded` feature. Object counts are checked
after parsing the size-bounded input. Dependencies must preserve these guards
when updated.

| Item | Rule |
| --- | --- |
| Entire document | At most 256 KiB, UTF-8, TOML 1.0 syntax; no BOM |
| Object counts | At most 128 actions, 32 resources, one managed secret per LUKS resource |
| IDs and references | 1–64 ASCII bytes; `[a-z][a-z0-9]*([._-][a-z0-9]+)*`; case-sensitive, no normalization |
| Description | 1–256 UTF-8 bytes, not whitespace-only; no control characters |
| Mapping name | 1–64 ASCII bytes; `[a-z][a-z0-9]*([_-][a-z0-9]+)*` |
| LUKS UUID | Exactly lowercase hexadecimal `8-4-4-4-12` groups; reject all-zero UUID; do not impose an RFC UUID version |
| Systemd unit | 1–128 ASCII bytes total; nonempty stem using the ID grammar followed by `.service` or `.target` |
| Execution timeout | Integer, 1–600 seconds |
| Output limit | Integer, 0–65,536 bytes; combined captured stdout/stderr budget |

Unit names are a deliberately restricted subset: no paths, globs, templates,
instances (`@`), escapes, whitespace or leading option characters. Broader unit
naming support can be reviewed later. `.target` permits an administrator-defined
group, but its successful start does not prove application health.

Execution timeout is proposed as one overall budget for the action after
required authentication/secret delivery, not a fresh budget per internal step.
Ceremony/secret-wait deadlines are separate and not specified here. An output
limit of zero means capture nothing; it does not remove execution limits.
Timeout cancellation and output-overflow behavior need execution design review
before runtime implementation, especially for systemd jobs that can outlive a
client request. Output capture limits do not authorize exposing raw output to
web clients or logs; secret-safe reporting remains mandatory.

## Cross-reference validation

- Every operation/prerequisite resource reference must name a declared resource
  of the kind required by that variant (initially `luks2`).
- Every LUKS resource must define exactly one managed secret with a valid ID.
  The same ID grammar applies to resources, actions and managed secrets.
- Reject duplicate TOML keys/tables and wrong scalar types; do not coerce values.
- Reject repeated LUKS UUIDs, mapping names or managed secret IDs across resources.
  Multiple actions may share a resource and thereby its managed secret.
  An unused resource is allowed; its declaration does not grant any authority.
- Reject legacy top-level `secrets`/`volumes` tables and `ensure_unlocked` fields;
  this draft replaces the earlier unimplemented representation.
- Multiple actions may target one unit. Their grants remain independent;
  conflicting concurrent requests need a separate runtime policy.
- Reject action references and dependency lists rather than trying to resolve a
  dependency graph. Unknown schema versions and operation kinds fail closed.

An unprovisioned secret is not a structural error: provisioning is a later
privileged operation. A structurally valid action may still be unavailable.
Do not read mutable state to determine whether a configuration parses.

## Offline CLI contract

Implemented command:

```text
wudo config validate --file examples/paperless.actions.toml
```

Require an explicit local file path for this initial command. It is an
unprivileged read-only CLI input, not a remote request or permission to install
configuration. No daemon contact, network request, command execution, LUKS
probe, systemd query, state mutation or secret access. Read only a bounded
regular file. On Linux the CLI uses `rustix` safe file-opening APIs with
`NOFOLLOW`, `NONBLOCK`, `NOCTTY` and `CLOEXEC`, then checks metadata on the opened
descriptor. Final-component symlinks and nonregular files are rejected; parent
symlinks are allowed. This prevents a final-path check/open race and FIFO waits.
Read at most the byte cap plus one, even if the file grows after metadata checks.
No root ownership or mode policy is imposed by this unprivileged validator.
It is not suitable as the future privileged daemon loader; parent trust,
filesystem races and concurrent-writer snapshot guarantees require that design.

Success output:

```text
Action configuration is structurally valid (3 actions, 1 resources, 1 managed secrets).
Deployment readiness was not checked.
```

Exit codes: `0` valid, `1` unreadable or invalid configuration, `2` CLI
usage error. Report one bounded diagnostic (at most 1 KiB) with a stable category
only. Line/column reporting is not implemented. Do not echo raw source lines, supplied values,
unknown field names, paths, or unsanitized parser/library errors: a malformed
input might accidentally contain a secret. Use known schema field names only.

Example diagnostic categories: `unsupported-schema`, `unknown-field`,
`invalid-value`, `missing-reference`, `conflicting-resource`, `input-too-large`,
`invalid-toml`, `invalid-schema`, and `input-unreadable`. Syntax errors map to
`invalid-toml`; missing fields and wrong types map to `invalid-schema`. No raw
third-party error is retained in the public `ConfigError`. Unknown kinds are
`invalid-value`; unknown field names are `unknown-field`.

## Runtime guarantees this validator cannot provide

The [SQLite identity storage contract](identity-persistence-proposal.md) records
the accepted isolated user-storage slice. Grant binding, privileged runtime
loading and recovery remain separate gates.

A successful offline check does not verify root ownership/permissions, safe
symlink handling, trusted parent directories, safe executable/unit definitions,
actual LUKS identity or version, uniqueness of live device matches, mapping
identity, mount source, service availability, credentials, grants, wrappers, or
provisioning readiness. UUID syntax is not proof of device identity.

The future daemon loader must enforce privileged filesystem checks, validate
its own inputs, reconcile configuration with state, and reject invalid input
before admitting actions. Changes to action targets under an existing ID must
not silently transfer grants to a different capability. Configuration activation,
reload, ID reuse and state migration need explicit decisions before loading this
configuration into a running daemon. No live reload is implemented by this task.

Mapping revalidation, concurrent actions, partial failure, cancellation, and
application-health reporting remain runtime design work under issue #16.
Stopping Paperless does not mean the SSD is locked. This proposal adds no
lock/close operation or automatic rollback.

## Acceptance tests

- Accept the example, empty object tables, root-only start/stop, unused
  resources, and multiple actions sharing a resource.
- Reject missing fields, unknown fields at each level, unknown versions/kinds,
  duplicate declarations and wrong types (including booleans/floats for limits).
- Reject command/argv/environment/path/dependency injection fields and fields
  belonging to another operation or prerequisite variant.
- Reject unknown resource/prerequisite kinds, mismatched resource references,
  unsupported prerequisite/operation combinations, lists of prerequisites,
  missing managed-secret definitions and the superseded draft fields.
- Test every size/count boundary at the maximum and just beyond it; reject
  negative/zero timeouts and oversized or excessively nested malformed input.
- Reject invalid IDs, mapping names, UUIDs, unit names and control characters.
- Reject missing references, duplicate resource identities and shared secret
  IDs across resources; do not require provisioned state to validate definitions.
- CLI tests cover unreadable/oversized/nonregular inputs, usage/exit codes and
  secret-like canary strings in malformed input that must not appear in output.
- Tests must need no root, real block device, systemd instance, network or secret.

Runtime tests for unauthorized users, revoked credentials, wrong/stale mappings,
conditional wrapper eligibility, and partial failures belong to later execution
and authentication implementations, not this offline parser.

## Review choices

The agreed ownership and conditional-secret model is preserved. The offline
implementation uses the schema, limits, resource-owned secret representation,
confirmation field and CLI contract above. No authorization, confirmation UX,
secret eligibility or runtime lifecycle decision follows from parsing these
fields. Runtime decisions listed above remain open before privileged execution.

Alternatives deferred: generic executable actions, recursive dependencies,
free-form step lists, duplicated resource definitions per action, and permissions
in static configuration. Typed operations keep targets and secret requirements
explicit while meeting the initial Pi use case.
