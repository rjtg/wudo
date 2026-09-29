# Domain Model

## User

A human principal.

A user can:
- own multiple credentials;
- be authorized for multiple actions.

Do not use credential IDs as user IDs.

## Credential

A WebAuthn/passkey credential belonging to a user.

Candidate metadata:
- stable credential ID;
- WebAuthn public key;
- user ID;
- display label;
- creation time;
- revoked state;
- PRF capability/metadata as needed.

No passkey private key or biometric data is stored.

## Action

A named administrator-defined capability such as:

```text
paperless.start
paperless.stop
system.reboot
```

An action may:
- require explicit confirmation;
- require a secret;
- execute a fixed program with fixed arguments;
- have timeout/output policies.

Clients refer only to the action ID.

## Authorization

A policy relationship:

```text
User -> may invoke -> Action
```

Authorization is user-level, not credential-level by default.

Authentication with one of the user's valid credentials establishes the user identity. Additional requirements may later constrain which credentials can satisfy a particular operation.

## Secret

A logical downstream secret required by one or more actions.

Definition and material are separate.

Example:

```text
Secret ID: paperless-luks
Type: LUKS key
State: UNINITIALIZED
```

After provisioning:

```text
State: READY
Wrappers:
  credential-A -> AEAD(KEK-A, K)
  credential-B -> AEAD(KEK-B, K)
```

## Credential wrapper

Cryptographic relationship:

```text
Credential -> can unwrap -> Secret
```

This is not itself the main action authorization policy. It expresses whether that credential can cryptographically recover the downstream secret.

## Important distinction

```text
User -------- authorization --------> Action
                                        |
                                      requires
                                        |
                                        v
                                      Secret
                                        ^
                                        |
Credential -------- wrapper ------------+
```

This separation lets:
- one user own multiple passkeys;
- multiple users be authorized for an action;
- multiple credentials wrap the same downstream secret;
- actions exist before their required secret is provisioned.

## Suggested secret states

Initial proposal:

- `UNINITIALIZED`: definition exists, no usable downstream material.
- `PROVISIONING`: transactional setup in progress.
- `READY`: usable.
- `ROTATING`: key rotation in progress.
- `ERROR`: recovery/intervention required.

Exact state transitions must be specified before implementation.
