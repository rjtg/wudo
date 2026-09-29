# Secret Design

## Goals

Wudo actions may depend on downstream secrets while keeping plaintext secret material out of `wudo-web`.

A downstream secret has:
- a logical ID;
- a type/backend;
- lifecycle state;
- encrypted wrappers for eligible credentials;
- downstream provisioning metadata.

## Definition before material

An action may reference a secret before that secret exists cryptographically.

Example:

```text
paperless.start
  requires: paperless-luks

paperless-luks
  state: UNINITIALIZED
```

An operation that needs to unlock storage cannot execute until its secret is
`READY` and the credential can unwrap it. For an ensure-unlocked prerequisite,
a daemon-verified existing mapping satisfies the prerequisite without secret
use. Authentication and action authorization still apply; see
[operations and prerequisites](domain-model.md#operations-and-prerequisites).

This avoids a bootstrap cycle between action definition, user authorization, credential enrollment and secret creation.

## Lifecycle

Conceptually:

```text
define
  -> authorize users
  -> provision
  -> use
  -> add/revoke credential wrappers
  -> rotate
  -> retire/delete
```

Provisioning is special: it combines local administrator authority with a credential capable of protecting the new secret.

## Key hierarchy for PRF-backed secrets

For credential `C` and downstream key `K`:

```text
PRF_C = WebAuthn_PRF(...)
KEK_C = KDF(PRF_C, context)
Wrap_C = AEAD_Encrypt(KEK_C, K, associated_data)
```

Requirements:
- use domain-separated KDF context;
- bind wrapper metadata with authenticated associated data;
- use standard library primitives;
- define versioning/algorithm IDs;
- never reuse nonce material incorrectly;
- do not design custom cryptographic primitives.

Exact algorithms are intentionally undecided until protocol design.

## Multiple credentials

One downstream key `K` may have many wrappers:

```text
Secret S
  K
  ├── Wrap(Credential A)
  ├── Wrap(Credential B)
  └── Wrap(Credential C)
```

This allows multiple passkeys without consuming a downstream LUKS slot for each credential.

## Revocation

Removing `Wrap(C)` prevents credential C from recovering K through Wudo in the future.

It does not revoke an already copied K.

For stronger revocation:
1. generate `K2`;
2. provision `K2` downstream;
3. create wrappers for remaining credentials;
4. verify recovery/unlock;
5. remove old downstream key `K`;
6. destroy old wrappers.

Rotation must be transactional and recoverable.

## Secret transport

Current threat model allows plaintext K in:
- browser memory, briefly;
- `wudod` memory, briefly.

It does not allow plaintext K in:
- `wudo-web`;
- logs;
- argv;
- persistent Wudo storage.

Browser-to-daemon transfer therefore requires end-to-end encryption with `wudo-web` acting only as a relay.

Use authenticated end-to-end encryption in both directions, including provisioning. The exact protocol and endpoint key authentication are open. Do not invent them during implementation.

The plaintext restrictions above describe the intended protocol. A compromised `wudo-web` can serve malicious UI that steals browser-held K during use; this is an accepted risk. No UI attestation is planned.
