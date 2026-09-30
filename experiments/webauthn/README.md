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
  features. Review this cost before approving a daemon dependency.
- Source inspection of 0.5.5's extension types found HMAC-secret fields but no
  WebAuthn `prf` fields. This harness does not establish PRF compatibility;
  browser-side PRF integration needs a separate design/test under #14. Never
  forward plaintext PRF output merely because a library type has secret fields.

These results support continuing the library evaluation, not treating #12 as
finished or the library as approved for privileged integration.

## Remaining gates

No real browser/authenticator or Raspberry Pi/ARM test has run. Counter anomaly
handling, backup flags, cross-origin/topOrigin policy, credential uniqueness,
userHandle handling, supported algorithm coverage, parsing bounds/extension
allowlists, logging redaction and error mapping need further validation.
Registration here tests one software authenticator, not attestation diversity.

Before runtime integration, review the dependency graph and exact input schemas,
choose persistent state/durability rules, implement bounded single-use operation
state, and finalize default/insecure enrollment semantics. API success is not
authorization and does not establish the intent shown by an untrusted UI.

Sources inspected: the downloaded 0.5.5 crate source and
[verifier API](https://docs.rs/webauthn-rs/0.5.5/webauthn_rs/struct.Webauthn.html),
[builder API](https://docs.rs/webauthn-rs/0.5.5/webauthn_rs/struct.WebauthnBuilder.html).
