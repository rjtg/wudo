# Installation setup

Status: accepted and implemented locally. Tracks #12, #15 and roadmap #20.

## Accepted user-facing behavior

Use one browser HTTPS origin per Wudo installation. Configure it through local
root administration during initialization, not during enrollment and not through
wudo-web or browser input.

```text
sudo wudo init --origin https://wudo.home.example
```

If the address is omitted in an interactive terminal, `sudo wudo init` asks for
it. For unattended use, required settings must be supplied as parameters; a
noninteractive invocation with missing settings reports what is required and
exits without writing state. Prompt input must be bounded and validated just
like explicit arguments. Do not prompt after a privileged mutation has started.

Derive the RP ID from the origin's hostname, following the already accepted
policy that the RP ID equals that hostname. Do not ask administrators to enter
the same hostname a second time. An origin includes the HTTPS scheme, hostname
and effective port; it is not an arbitrary URL containing a path, query or
fragment. The final validation/normalization rules belong in the implementation
contract and must be enforced by the daemon, independently of CLI validation.

Store the installation settings durably. Enrollment and authentication obtain
their RP/origin settings from this trusted state. Enrollment cannot set or
replace the installation origin. The browser and relay cannot select another
origin. Only one configured address is supported in the initial implementation.

Use the same parameter-or-interactive-prompt approach for other required
installation settings as they are defined. This does not add unspecified
configuration fields, move secret material into command-line arguments, or
replace administrator-defined action configuration with a generic setup editor.
Optional settings may use documented defaults. Secrets must never go in argv.

## Wire and persistence contract

New root-only v2 operation `installation.initialize` accepts exactly
`{origin: text(1..270)}` and returns `{state:"ready"}` only after persistence.
Request/reply caps are 4096 bytes. The daemon independently validates the origin.
The existing `store.initialize` operation retains its empty-body contract for
older clients; it creates unconfigured identity storage, never enrollment
readiness. Older daemons reject the new operation rather than silently ignoring
settings; the CLI never falls back to the legacy operation.

Validation accepts `https://` followed by lowercase ASCII DNS labels (1–63
characters, alphanumeric ends, internal hyphens, total hostname <=253 bytes)
and an optional decimal port 1–65535. IP literals, alternate numeric IP forms,
userinfo, uppercase/Unicode hostnames, whitespace, escaped hostnames, paths,
queries, fragments and noncanonical port strings are rejected. A single root
slash and explicit `:443` normalize away; other ports are preserved. International
names must be supplied in their ASCII form. RP ID is derived from the validated
hostname. No deployment DNS or TLS reachability check is implied.

Schema v3 adds a singleton installation row containing the canonical origin.
Fresh initialization creates the schema, then stores settings in an IMMEDIATE
transaction before replying. An interrupted attempt may leave a valid,
unconfigured store; explicit init can finish it after restart. There is no
implicit reset or automatic retry after an uncertain response.

For an existing v1/v2 store, run `sudo wudo upgrade` first. The migration preserves
users/credentials and leaves the installation unconfigured. Then run
`sudo wudo init --origin https://wudo.home.example`. Configuration succeeds only
when there are no existing credentials (including revoked records). Historical
credential records have no trustworthy origin binding; assigning them requires
separate explicit recovery work, not automatic adoption. Existing users are
preserved. Stores needing upgrade remain maintenance-only.

Normal init returns conflict, even for the same origin. Only the explicit reset
operation below can replace settings; preserving identities while changing the
origin remains separate migration work. Persisted settings are checked for exact schema and canonical
validity on every open. The enrollment core constructs its verifier exclusively
from stored settings and refuses an unconfigured store. Enrollment IPC and CLI
are described in [enrollment](enrollment-implementation.md).

Only the origin is currently an installation setting. The parameter/prompt
pattern is ready to extend when other required settings are defined.

## Validation

Tests cover the URL grammar and normalization, malformed/unknown/duplicate IPC
fields, endpoint policy, old IPC compatibility, missing noninteractive parameters,
bounded prompt input, persistence/restart, v2 upgrades preserving users, immutable
settings, historical-credential refusal, invalid persisted origins and verifier
construction from stored settings. Socket-level tests exercise initialization
and denied web requests. The privileged smoke harness supplies an explicit
origin and remains a separate maintainer-run deployment check.

## Explicit reset

```text
sudo wudo init --reset --origin https://wudo.home.example
# Unattended:
sudo wudo init --reset --yes --origin https://wudo.home.example
```

Interactive reset requires typing `RESET`; `--yes` explicitly skips that prompt.
Noninteractive reset requires `--yes`. Missing origin still prompts only on a
terminal. All confirmation and input validation happen before sending a request.
`--yes` without `--reset` is invalid. There is no automatic retry.

The separate root-only v2 `installation.reset` operation accepts exactly the
same `{origin}` body/caps as initialization. Kernel root identity and endpoint
policy establish authority; CLI confirmation is a local safeguard, not a
browser-provided authorization claim.

Reset deletes every stored user and active/revoked credential and replaces the
origin in one SQLite transaction. Pending opportunities/candidates are discarded
before the transaction, even if it fails. Late verifier results cannot activate
across reset, including a reset to the same origin. Worker capacity remains held
until those old jobs complete. Success is returned only after commit; failure
rolls back persistent changes and storage failures require restart/inspection.
This is logical deletion, not guaranteed forensic erasure from the storage medium.

Action configuration files, system services, disks, LUKS keyslots and recovery
passphrases are untouched. Grants and secret wrappers are not yet implemented;
future schemas must explicitly extend reset semantics before supporting them.
Deletion of wrappers may remove Wudo-mediated access but never substitutes for
rotating a leaked downstream key. Reset does not bypass schema/filesystem
validation: upgrade known old layouts first; corrupt/unsafe stores require local
repair rather than unchecked file deletion. A missing store is initialized with
the supplied origin. Historical credentials can be discarded by this explicit
reset, rather than silently rebound to a different installation.
