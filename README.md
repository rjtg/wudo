# Wudo

**Wudo** means **Web User Do** and is pronounced "voodoo".

Wudo is a passkey-authenticated privilege broker for Linux. It lets users invoke administrator-defined privileged actions from a browser without exposing a remote shell or arbitrary command execution.

> Users choose what to do, never what to execute.

## Planned components

```text
Browser
  |
  | HTTPS / WebAuthn
  v
wudo-ui
  |
  v
wudo-web                 unprivileged, network-facing
  |
  | Unix-domain socket
  v
wudod                    privileged security boundary
  |
  v
fixed administrator-defined actions

wudo-cli
  |
  | local administrative IPC
  v
wudod
```

- **wudod** — privileged daemon and enforcement point.
- **wudo-web** — unprivileged web/API service; assume compromise.
- **wudo-ui** — browser UI, WebAuthn and PRF operations.
- **wudo-cli** — local bootstrap, recovery, configuration and administration.

## Initial reference use case

The first concrete use case is remotely starting an encrypted Paperless installation after reboot:

1. User selects `paperless.start`.
2. User authenticates with a passkey.
3. The browser uses WebAuthn PRF to unwrap a random Wudo-managed LUKS key.
4. The browser encrypts that key directly for `wudod`.
5. `wudo-web` only relays ciphertext.
6. `wudod` unlocks LUKS and runs the preconfigured start action.

The existing human LUKS passphrase remains as a recovery mechanism.

## Design status

This repository is intentionally design-first. See:

- `SECURITY.md`
- `docs/architecture.md`
- `docs/domain-model.md`
- `docs/secrets.md`
- `docs/luks-flow.md`
- `docs/open-questions.md`
- `tasks/000-roadmap.md`

Do not treat unresolved cryptographic or authorization protocol details as finalized.
