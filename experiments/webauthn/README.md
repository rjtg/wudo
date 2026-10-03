# WebAuthn verifier experiment

This is an isolated, test-only suitability harness for #12. It has its own
workspace and lockfile. None of its dependencies are added to `wudod` or the
application workspace. It is not an enrollment service or production API.

Run from the repository root:

```text
cargo fmt --manifest-path experiments/webauthn/Cargo.toml --check
cargo clippy --manifest-path experiments/webauthn/Cargo.toml --all-targets --all-features --locked -- -D warnings
cargo test --manifest-path experiments/webauthn/Cargo.toml --locked
```

Build prerequisites: stable Rust, a C toolchain, pkg-config and OpenSSL
development headers/libraries. The lockfile pins the tested dependency graph.
The repository CI has a separate job for this experiment; ordinary workspace
tests do not discover it.

## What is exercised

`webauthn-rs` 0.5.5 performs verification; the matching upstream software
authenticator produces real synthetic credential keys and signatures. Its
`SoftPasskey::new(true)` simulates the UV flag. This proves verifier behavior
with signed fixtures, not real biometric/PIN interaction or hardware security.
The fake authenticator exists only as a dev dependency. No real credentials,
network listener, root access or persistent credential database are used.

Eight tests cover registration/authentication success, credential metadata
updates, wrong registration/authentication challenges, wrong credential,
signature corruption, signed subdomain/port mismatches, a signed wrong RP hash,
and signed responses without UV. The RP-hash test keeps the origin correct to
isolate that check. Values such as `wudo.example.test` are synthetic fixtures,
not a proposed installation hostname.

## Findings

- The high-level passkey API supports the basic ceremony split and enforces UV
  against the server's state even when client options are downgraded. Explicit
  `allow_subdomains(false)` and `allow_any_port(false)` reject the tested origin
  mismatches in both registration and authentication.
- Verification state is reusable: verifying the same assertion twice against
  the same unchanged state succeeds twice. This is the library API contract,
  not a library vulnerability. Wudo must atomically consume its own pending
  challenge record and enforce expiry, identity/action binding and revocation.
- The builder accepts HTTP origins and parent-domain RP IDs that Wudo excludes.
  Application configuration validation must enforce Wudo's narrower approved
  policy; the builder is not a substitute for that validation.
- Even with default features disabled, the verifier transitively includes
  OpenSSL/openssl-sys, Serde JSON/CBOR, ASN.1 and X.509 parsers, URL/IDNA handling
  and tracing. Disabling the high-level attestation feature does not eliminate
  those core dependencies. The experiment enables no dangerous verifier
  features. This evaluated cost has been accepted for daemon integration.
- Source inspection of 0.5.5's extension types found HMAC-secret fields but no
  WebAuthn `prf` fields. This harness does not establish PRF compatibility;
  browser-side PRF integration needs a separate design/test under #14. Never
  forward plaintext PRF output merely because a library type has secret fields.

The verifier choice and evaluated dependency footprint are now approved for
daemon integration. These results do not finish #12 or validate untested policies.

## Remaining gates

The [parser-gap investigation](../../docs/webauthn-parser-gap.md) adds three
parser-only characterization tests (15 experiment tests total). The direct
`webauthn-rs-core` dev dependency exposes the pinned library's existing parser
for those tests only. It accepts structures outside Wudo's stricter profile;
post-parse checks cannot recover lost duplicate-key evidence. No custom parser,
production dependency was introduced by the tests. The maintainer subsequently
deferred the extra inner restrictions; they no longer block enrollment work.

No real browser/authenticator or Raspberry Pi/ARM test has run. Counter anomaly
handling, backup flags, cross-origin/topOrigin policy, credential uniqueness,
userHandle handling, supported algorithm coverage, parsing bounds/extension
allowlists, logging redaction and error mapping need further validation.
Registration here tests one software authenticator, not attestation diversity.

Before runtime integration, review exact input schemas and any dependency changes,
choose persistent state/durability rules, implement bounded single-use operation
state, and finalize default/insecure enrollment semantics. API success is not
authorization and does not establish the intent shown by an untrusted UI.

Sources inspected: the downloaded 0.5.5 crate source and
[verifier API](https://docs.rs/webauthn-rs/0.5.5/webauthn_rs/struct.Webauthn.html),
[builder API](https://docs.rs/webauthn-rs/0.5.5/webauthn_rs/struct.WebauthnBuilder.html).

## Wire and credential compatibility slice

Four additional tests bring this harness to twelve tests. It now uses the
existing `wudo-protocol/v2` crate as a dev dependency. OpenSSL and serde_json are
direct dev dependencies for fixtures; both were already in the experiment graph.
No application runtime dependency or enrollment handler changed.

- A high-level public `Passkey` survives JSON serialization/reload, verifies an
  assertion, persists updated metadata, and verifies again after another reload.
  This synthetic credential fits 16 KiB; that is not a maximum-size guarantee or
  approval of an unversioned production format. Strict stored-record validation,
  historical compatibility and other algorithms remain open.
- Registration verification uses the credential ID inside attestation. Changing
  outer `id`/`rawId` does not change the verified identity. The adapter must compare
  the verifier-returned ID with wire `credential_id` before candidate binding,
  fingerprint display or persistence. Verification success alone does not validate
  an outer ID.
- Upstream SoftPasskey emits `tokenBinding:null`. The verifier accepts it, but
  Wudo's approved strict client-data profile rejects it. The test characterizes
  this mismatch without relaxing the policy. Browser compatibility still needs
  measurement before deciding whether the profile should change.
- The positive wire fixture constructs compliant client-data JSON BEFORE signing,
  hashes it through OpenSSL and calls upstream's hashed-client-data authenticator
  API. Registration and assertion cross Wudo encode/decode without modifying signed
  bytes and verify successfully. No custom authenticator-data or cryptographic
  parser is introduced. Browser option projection, client extension variants and
  nonempty user handles are not covered by this test.

Deferred parser hardening: authenticator-data internals, including COSE and extension
CBOR, remain opaque to Wudo's codec. Pinned core source uses internal CBOR parser
paths; Wudo does not enforce the extra duplicate/depth/item/trailing-byte
restrictions there. The maintainer accepted that behavior for now; implementation
is deferred, not a runtime integration gate. Public-credential serialization feasibility does not settle activation,
revocation, ownership, replay consumption or durable update policy.
