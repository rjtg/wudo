# Open Design Questions

These items must not be silently guessed by an implementation agent.

## 1. Daemon-side WebAuthn ceremony details

Tracking: [#12](https://github.com/rjtg/wudo/issues/12).

The [ceremony proposal](webauthn-proposal.md) now records candidate policies,
enrollment risks, limits and tests. It is a draft; trusted enrollment UX,
persistence ordering and concrete wire schemas remain implementation gates.

Decided: `wudod` creates challenges, verifies actual WebAuthn registration/authentication responses, and checks user authorization. `wudo-web` relays messages; neither it nor the UI can assert trusted authentication or authorization.

Decided: each installation configures one exact HTTPS origin and an RP ID
matching its hostname in trusted daemon settings. No hardcoded deployment name
or origin inferred from browser/relay requests. RP ID changes can require
re-enrollment. The explicit local `enroll --insecure` option is also accepted;
see the ceremony proposal for its bounded scope and enrollment takeover risk.

Decided: one fresh passkey verification per action invocation, covering its
internal steps; no reusable action-authorizing session. A malicious UI can
misrepresent the action, which is an accepted risk. No daemon-signed challenge
or UI attestation is added to try to prove displayed intent.

Still specify:
- established verifier library and bounded input schemas;
- origin/RP configuration schema and migration handling;
- required user-verification properties;
- operation/action and principal binding;
- expiry, single-use challenge consumption, and concurrency/replay handling;
- enrollment and recovery binding to local administrative authority;
- binding to any required secret operation.

A valid assertion does not prove which action the UI displayed. Malicious UI delivery is an accepted risk; UI attestation is out of scope.

## 2. Browser-to-wudod secret transport

Tracking: [#13](https://github.com/rjtg/wudo/issues/13).

Define a standard authenticated end-to-end encryption protocol for UI ↔ `wudod`, including provisioning and normal use. Relay messages must not expose plaintext K. This does not protect against malicious UI delivery, which is an accepted risk.

Questions:
- static daemon key vs ephemeral/session key;
- authentication of daemon public key to browser;
- replay/session binding;
- forward secrecy requirement;
- protocol versioning;
- key rotation and persistence.

## 3. WebAuthn PRF compatibility

Tracking: [#14](https://github.com/rjtg/wudo/issues/14).

Validate the actual target platform(s), initially including a modern Android/Chrome/passkey setup.

Define fallback behavior when PRF is unavailable.

## 4. Configuration ownership

Tracking: [#15](https://github.com/rjtg/wudo/issues/15).

The [offline schema and validation contract](configuration-proposal.md) and
[Paperless example](../examples/paperless.actions.toml) are implemented in the
first slice of #3. Runtime loading and execution remain unimplemented.

Decided: root-owned configuration defines available actions, fixed targets,
secret definitions, and limits. The daemon manages users, credentials and
authorization grants, with grant/revoke/list operations through the local
administrative CLI. Wrappers and provisioning state are daemon-managed.

Offline schema versioning, IDs and bounds are documented in the configuration
contract. Still specify runtime reload semantics, persistence, revocation timing
and administrative IPC. Offline structural validation must
be distinguished from runtime readiness and privileged filesystem checks.

## 5. Action execution model

Tracking: [#16](https://github.com/rjtg/wudo/issues/16).

Decided: user-facing actions contain internal operations, not recursive action
dependencies. Initial shapes are LUKS unlock, fixed systemd unit start/stop,
and ensure-unlocked then fixed unit start. Systemd handles mounts and application
orchestration. See [domain model](domain-model.md#operations-and-prerequisites).

An already-unlocked mapping verified by the daemon requires no secret again;
authentication and authorization still apply. Exact mapping verification,
state-change/concurrency handling, timeouts, service success criteria, and
partial-failure behavior remain to be specified. Generic fixed executables or
administrator scripts are deferred, not implicitly enabled by this decision.

## 6. Provisioning transaction

Tracking: [#17](https://github.com/rjtg/wudo/issues/17).

Specify crash-safe LUKS provisioning and rotation:
- when state changes;
- when wrapper is persisted;
- when LUKS slot is added/removed;
- verification before commit;
- rollback/recovery behavior.

## 7. Multi-user scope

Tracking: [#18](https://github.com/rjtg/wudo/issues/18).

The data model should support users and multiple credentials. Decide whether full multi-user authorization is required in the first usable release.

## 8. UI stack

Tracking: [#19](https://github.com/rjtg/wudo/issues/19).

Decided: Rust compiled to WebAssembly, served by `wudo-web`, with browser bindings and generated JavaScript glue as needed. Choose a small frontend framework only after protocol/domain boundaries are stable.
