# Open Design Questions

These items must not be silently guessed by an implementation agent.

## 1. Daemon-side WebAuthn ceremony details

Tracking: [#12](https://github.com/rjtg/wudo/issues/12).

Decided: `wudod` creates challenges, verifies actual WebAuthn registration/authentication responses, and checks user authorization. `wudo-web` relays messages; neither it nor the UI can assert trusted authentication or authorization.

Still specify:
- established verifier library and bounded input schemas;
- configured RP ID/origin and required user-verification properties;
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

Decide which objects live in static root-owned configuration versus mutable privileged state:
- actions;
- secret definitions;
- users;
- authorizations;
- credentials.

Prefer a model that remains auditable and recoverable.

## 5. Action execution model

Tracking: [#16](https://github.com/rjtg/wudo/issues/16).

Decide whether an action is:
- one fixed executable + fixed argv;
- a sequence of typed built-in privileged operations;
- or both.

Do not use shell scripts merely to avoid specifying this.

Existing administrator-owned scripts may be acceptable as fixed executables, but ownership/permissions and trust implications must be documented.

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
