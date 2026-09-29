# Open Design Questions

These items must not be silently guessed by an implementation agent.

## 1. Agent-verifiable web authorization

If `wudod` accepts an action solely because the Unix peer is `wudo-web`, compromising `wudo-web` permits invocation of every configured action.

Define how `wudod` can verify a short-lived authorization derived from successful WebAuthn authentication.

Desired properties likely include:
- action binding;
- user/principal binding;
- expiry;
- nonce/replay protection;
- confirmation/fresh-auth requirements;
- binding to any required secret operation.

Avoid custom cryptography.

## 2. Browser-to-wudod secret transport

Define a standard end-to-end encryption protocol so `wudo-web` cannot read plaintext K.

Questions:
- static daemon key vs ephemeral/session key;
- authentication of daemon public key to browser;
- replay/session binding;
- forward secrecy requirement;
- protocol versioning;
- key rotation and persistence.

## 3. WebAuthn PRF compatibility

Validate the actual target platform(s), initially including a modern Android/Chrome/passkey setup.

Define fallback behavior when PRF is unavailable.

## 4. Configuration ownership

Decide which objects live in static root-owned configuration versus mutable privileged state:
- actions;
- secret definitions;
- users;
- authorizations;
- credentials.

Prefer a model that remains auditable and recoverable.

## 5. Action execution model

Decide whether an action is:
- one fixed executable + fixed argv;
- a sequence of typed built-in privileged operations;
- or both.

Do not use shell scripts merely to avoid specifying this.

Existing administrator-owned scripts may be acceptable as fixed executables, but ownership/permissions and trust implications must be documented.

## 6. Provisioning transaction

Specify crash-safe LUKS provisioning and rotation:
- when state changes;
- when wrapper is persisted;
- when LUKS slot is added/removed;
- verification before commit;
- rollback/recovery behavior.

## 7. Multi-user scope

The data model should support users and multiple credentials. Decide whether full multi-user authorization is required in the first usable release.

## 8. UI stack

Choose only after protocol/domain boundaries are stable. Keep the UI simple.
