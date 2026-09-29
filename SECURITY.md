# Wudo Security Model

## Primary security objective

Wudo must not turn a network-facing application into arbitrary root command execution.

The root daemon exposes capabilities, not a shell.

## Core invariant

> Users choose an administrator-defined action ID. They never provide executable code, executable paths, arbitrary argv, arbitrary environment variables, or arbitrary privileged paths.

## Trust model

### Trusted / privileged

`wudod` is trusted and privileged. Its code, configuration and persistent state form part of the trusted computing base.

Local root administration is the ultimate recovery authority.

### Untrusted

`wudo-web` is network-facing and must be treated as potentially fully compromised.

A compromise must not provide arbitrary root execution. In the intended protocol, the web service relays only encrypted downstream secrets. This protects against disclosure through relay payloads; it does not protect against active replacement of the UI served by that service.

### Browser

The browser is trusted for the duration of an authenticated operation in the current threat model.

It is acceptable for the browser to briefly hold:
- WebAuthn PRF-derived material;
- a derived KEK;
- plaintext downstream key `K`.

A browser compromise at the right moment may steal `K`. A compromised `wudo-web` can also serve malicious UI that steals `K` during subsequent use or misrepresents the action being authenticated. Both are accepted risks. Rust/WASM does not authenticate delivered application code; UI attestation is out of scope.

WebAuthn proves authentication under the verified ceremony conditions, not the integrity of the UI or the action text it displayed. The daemon still independently enforces action binding and user authorization.

### Passkey authenticator

The authenticator protects the passkey private key. Wudo stores public credential data only.

For secrets, Wudo may depend on WebAuthn PRF. PRF support must be verified for supported browser/authenticator combinations.

## Privilege separation

```text
network/browser
      |
      v
wudo-web (unprivileged; assume compromise)
      |
====== Unix IPC / privilege boundary ======
      |
      v
wudod (root; no network listener)
      |
      v
fixed actions / downstream privileged resources
```

`wudo-cli` is a separate local administrative client. Administrative operations must not become available to `wudo-web` merely because both use IPC.

## Process execution

Forbidden:
- shell execution;
- command strings;
- client-selected executables;
- client-controlled argv;
- client-controlled environment;
- client-controlled working directories for privileged execution.

Allowed action execution is loaded from trusted administrator-controlled configuration and executed directly.

Executables/configuration should be checked for appropriate ownership, permissions, file type and symlink behavior.

## Secrets

Secrets must not appear in:
- logs;
- URLs;
- argv;
- panic output;
- user-visible errors;
- audit metadata.

Prefer stdin/pipes/file descriptors when a child process needs a secret.

Plaintext secret buffers should have short lifetimes and be zeroized where practical.

Persistent Wudo state contains encrypted/wrapped downstream secrets, not plaintext downstream keys.

## Network-facing compromise

The design must assume an attacker can control all behavior of `wudo-web`.

Therefore Unix-socket possession alone must not implicitly mean "authorized for every action."

`wudod` creates WebAuthn challenges, verifies registration/authentication responses using an established library, checks authorization, and executes only fixed administrator-defined actions. It trusts no authentication or authorization claims from the web service or UI. It has no HTTP parser or network listener.

Challenges must be short-lived, single-use, and bound to the intended operation. Detailed ceremony schemas, replay handling, and secret-operation binding remain open. Authenticated encryption between the UI and daemon protects secret transport; its exact protocol and endpoint key authentication remain to be specified.

## Conditional secret use

Authentication and action authorization apply even when storage is already
unlocked. Only daemon verification of the expected device mapping may satisfy
the unlock prerequisite without a secret. UI/web claims, a matching mapping
name alone, or stale observations are insufficient. Secret-wrapper eligibility
is required when unwrapping a key, not when an already-satisfied prerequisite
requires no key. No plaintext key cache is introduced.

## Availability and abuse controls

Bound:
- HTTP request size;
- IPC message size;
- concurrent requests;
- child execution duration;
- captured stdout/stderr;
- audit record sizes.

Failure should not leave half-provisioned secrets or ambiguous state.

## Recovery

Wudo must not make the passkey the only recovery mechanism for the host.

For the LUKS use case:
- retain the existing human LUKS recovery passphrase;
- use a separate random Wudo key in another keyslot;
- permit local root to enroll replacement credentials.

## Revocation semantics

Credential revocation is not equivalent to secret rotation.

Deleting a credential's encrypted wrapper prevents future Wudo-mediated unwrapping with that credential. It cannot invalidate a copy of the downstream key that was already obtained.

True cryptographic revocation requires rotating the downstream key.

## Out of scope for initial versions

- arbitrary remote shell;
- arbitrary command execution;
- generic privileged file manager;
- generic plugin system executing supplied code;
- protection against a fully compromised root/kernel;
- protection of a LUKS key from a browser compromised exactly while that key is being used.

## Security review triggers

Require explicit review before:
- adding a new IPC operation to `wudod`;
- adding dependencies to the privileged daemon;
- changing authorization grant semantics;
- changing secret transport/wrapping;
- allowing any new client-controlled process parameter;
- adding privileged filesystem operations;
- introducing `unsafe`;
- changing bootstrap or recovery semantics.
