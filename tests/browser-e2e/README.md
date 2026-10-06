# Container browser enrollment test

Validation: the maintainer confirmed the complete harness passes on 2026-10-06.

From the repository root, with Docker Engine running:

```sh
python3 scripts/browser-e2e.py
```

If your account cannot access the Docker socket, run the same command with
`sudo`. The runner invokes Docker; no local Rust, Node, browser, certificate
installation, DNS configuration or running Wudo instance is needed. The first
build downloads the toolchain, dependencies and Chromium image and can take a
while. Subsequent builds reuse Docker layers.

The test builds the actual CLI, daemon, web service and WASM UI. In a disposable
container it runs root `wudod`, UID/GID 61001 `wudo-web`, nginx as the separate
HTTPS proxy, and Playwright Chromium with a CDP virtual CTAP2 authenticator.
It generates a fresh test CA and installs it into the container's browser trust
store. Certificate validation stays enabled. The application has no testing
bypass; only the authenticator hardware/user interaction is simulated.

Checks:

- Trusted HTTPS loads the actual WASM UI.
- Code-based registration remains inactive until exact local candidate approval.
- The browser-created credential is active after approval and daemon restart.
- A cancelled enrollment code is rejected without creating a credential.
- Explicit insecure enrollment on a second virtual authenticator activates a
  distinct credential without approval; the original credential remains excluded.

The container uses no host mounts, published ports, host network, Docker socket
mount, or privileged mode. Runtime networking is disabled; `wudo.test` resolves
only to its own loopback. Its state and certificates are disposable, and the
runner removes its container even after failure/timeout. Build downloads need
network access. The cached image stays available for subsequent runs.

Chromium uses Playwright's default container launch (browser sandbox disabled);
it accesses only this test application. This is a test appliance, not a Wudo
deployment image. The web service still runs without root or supplementary
groups, and production IPC peer checks remain enabled.

Failures report the current stage and full exception traceback. Verbose diagnostics
include CLI output, synthetic enrollment tickets, browser console/errors,
client-data JSON, enrollment response CBOR in hexadecimal, and service output.
This logging is explicitly intended for the isolated, freshly generated test
identities; it does not change production logging. Original WebAuthn bytes are
not rewritten, and authenticator private keys are not exported.
No physical authenticator, mobile browser, PRF, ARM, LUKS or action execution is
validated by this test. Real-device checks remain necessary.

References: [Playwright browser launch](https://playwright.dev/docs/api/class-browsertype#browser-type-launch),
[Chromium virtual authenticator API](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/).
