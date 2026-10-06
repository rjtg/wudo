# Browser enrollment

Status: implemented locally; real-device validation pending. This is the first web/UI slice under
#6/#7/#12/#19 and roadmap #20. It uses the existing registration protocol;
no administrative or action operations are exposed to HTTP.

## Deployment decision and stack

The maintainer chose a separate HTTPS service. `wudo-web` listens only on a
loopback address (default `127.0.0.1:8080`) and refuses root execution. The HTTPS
proxy runs on the same host. It forwards the browser's original Host and Origin
headers without rewriting Origin; forwarding headers never establish identity.

Axum supplies routing/body integration, with Hyper's HTTP/1 connection driver
and Tokio for explicitly bounded connections. Rust `wasm-bindgen` and `web-sys`
provide the small enrollment UI and browser API bindings. No reactive frontend
framework is needed for this one-page form. This does not select a framework
for a future action dashboard. Generated JavaScript is browser glue; enrollment
logic and WebAuthn option mapping are Rust compiled to WASM.

References: [Axum](https://docs.rs/axum/0.8.9/axum/),
[web-sys bindings](https://wasm-bindgen.github.io/wasm-bindgen/web-sys/index.html).

## Build and launch

From the repository root, as your normal development user:

```text
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129 --locked
python3 scripts/build-ui.py
cargo build --workspace --locked
```

The build script checks the matching tool version. It creates only generated
assets under `ui/wudo-ui/pkg/`; those files are ignored by Git. CI must build the
WASM target explicitly, since native workspace checks do not compile browser
bindings. Install the built assets somewhere readable by the web service.

Run `wudod` with the existing root-owned state/socket directory setup and the
UID/GID of a dedicated unprivileged web-service account. Run the following as
that account, whose UID must match the daemon's `--web-uid`:

```text
/path/to/wudo-web --origin https://wudo.home.example --assets /path/to/wudo-ui/pkg
```

An optional `--listen 127.0.0.1:8080` selects the local upstream port. Wildcard,
non-loopback and ephemeral-port binds are rejected. There is no TLS bypass or
plain-HTTP browser enrollment mode. Browser access requires trusted HTTPS.

`wudo init --origin` remains the authority for WebAuthn installation identity.
The web-service `--origin` is an HTTP allowlist and must match it; it neither
sets nor overrides daemon configuration. A mismatch fails at HTTP checks or
WebAuthn verification. No origin is inferred from browser or proxy headers.

For example, on an existing Caddy installation with DNS and certificate issuance
configured for the chosen hostname:

```text
wudo.home.example {
    reverse_proxy 127.0.0.1:8080
}
```

Use a real deployment hostname, not this placeholder. For a private hostname,
Caddy's `tls internal` can use its local CA, but that CA must be trusted on every
browser device; bypassing certificate warnings is not a deployment solution.
See [Caddy reverse proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)
and [TLS configuration](https://caddyserver.com/docs/caddyfile/directives/tls).
This repository does not install or alter your proxy, DNS, accounts, certificates
or host services. Disable proxy request-body logging and caching for Wudo. Do
not place enrollment tickets in URLs, access logs or proxy configuration.

## Enrollment walkthrough

For a fresh installation, initialize the daemon and create a user locally:

```text
sudo wudo init --origin https://wudo.home.example
sudo wudo user create alice --label Alice
sudo wudo enroll alice
```

For an existing initialized installation, use its existing origin/user rather
than resetting it. Open that HTTPS address in the browser, paste the private
one-time enrollment code, and choose **Create passkey**. The UI clears the input
and sends the ticket only in a POST body. It stores no tickets or credentials
in browser storage and uses no sessions, cookies, analytics or service worker.

The browser calls `navigator.credentials.create()` with daemon-generated
challenge, RP/user/options and required user verification. It sends the original
`clientDataJSON` and attestation bytes; it never reparses and reserializes signed
client data. The daemon independently validates the actual registration.

Default enrollment ends in **pending approval**. Root uses the enrollment ID
printed by the CLI to inspect and approve the exact candidate:

```text
sudo wudo enroll inspect ENROLLMENT_ID
sudo wudo enroll approve ENROLLMENT_ID CANDIDATE_ID
```

The UI shows the full public credential ID for inspection/recovery. Neither that
ID nor a fingerprint proves human ownership against malicious UI substitution;
the previously accepted enrollment threat model is unchanged.

For explicitly insecure enrollment, root starts `sudo wudo enroll alice --insecure`
and the browser user selects **My administrator opened enrollment without a
code**. This cannot create an opportunity or select a user; it discovers the
existing root-opened insecure window. Its first-valid-registration risk remains
explicit. Success adds a credential, not grants or secret wrappers.

A lost reply may mean the daemon completed registration. The UI does not retry
requests automatically; retain its displayed public ID and ask root to use
`wudo credential list alice` / `wudo credential show alice ID` and/or enrollment
inspection. Pending approval is not shown as active. Browser authentication,
action execution, PRF and secret transport remain out of scope for this slice.

## HTTP and transport boundaries

- Only exact GET paths `/`, `/style.css`, `/start.js`, `/wudo_ui.js` and
  `/wudo_ui_bg.wasm` serve assets. Assets are bounded and loaded once at startup;
  request paths never become filesystem paths.
- Only POST `/api/enroll` relays requests. It requires the configured exact Origin
  and Host, `application/cbor`, no content encoding, and same-origin Fetch
  Metadata when present. Query strings, CORS preflights and redirects are not
  enrollment mechanisms. No permissive CORS headers are emitted.
- The body is one existing CBOR v2 message without the Unix frame header. The
  explicit allowlist is registration.begin, registration.begin_insecure and
  registration.finish. No generic IPC proxy or status/admin/action route exists.
- HTTP bodies are capped at 40960 bytes; strict per-operation limits and schema
  validation apply before Unix IPC. Replies are framed, bounded, context-decoded
  and checked for EOF. The relay checks the daemon's kernel UID is root before
  sending any bytes. It never retries an uncertain mutation.
- At most 16 admitted HTTP connections; no keepalive/pipelined reuse, 32 headers,
  16 KiB header buffer, three-second header timeout and ten-second whole-connection
  timeout. Unix exchanges have a five-second absolute deadline. Browser POSTs
  also have a ten-second abort timer and bounded incremental response reads.
- Responses use no-store, nosniff, no-referrer, frame denial and restrictive CSP.
  WebAssembly compilation is allowed without allowing arbitrary JavaScript eval.
  Errors are fixed categories; request bodies, tickets and raw library errors
  are never logged. These HTTP controls are defense in depth, not daemon trust.

## Validation and remaining deployment checks

The [container browser test](../tests/browser-e2e/README.md) automates enrollment,
local approval, restart persistence, cancellation and explicit insecure mode:

```text
python3 scripts/browser-e2e.py
```

It requires a running Docker Engine (use `sudo` if needed for socket access).
It builds all components and uses trusted test HTTPS and Chromium's virtual
authenticator inside a disposable container. The maintainer confirmed a complete
passing run on 2026-10-06, including approval, restart persistence, cancelled-code
rejection and insecure enrollment with a second virtual authenticator. This does
not replace physical authenticator validation.

Automated tests cover operation allowlisting, malformed/oversized input, root-peer
checks, reply framing/EOF, cross-origin and media-type rejection, static-path
allowlisting, and exact browser option byte mapping. Native workspace tests,
native and WASM Clippy, two WASM adapter tests under Node, and the release WASM
asset build passed. CI builds and tests the WASM target separately.

Real browser/authenticator registration through trusted HTTPS, manual approval,
insecure mode, cancellation, expiry, origin mismatch and lost-reply recovery
still require a target-device deployment check. Do not equate synthetic verifier
or WASM adapter tests with browser/authenticator compatibility. ARM and PRF
validation remain separate. The deferred inner-CBOR rules remain deferred.
