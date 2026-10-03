# Deferred authenticator-data parser hardening

Status: **explicitly deferred by maintainer decision; not an enrollment blocker**.
Tracks #12. Reproducer: [parser_bounds.rs](../experiments/webauthn/tests/parser_bounds.rs).

## Accepted decision (2026-10-03)

Proceed with the established high-level WebAuthn verifier without adding these
extra inner-parser checks now. Wudo does not currently enforce duplicate-key
rejection, complete consumption of authenticator data, an indefinite-length CBOR
ban, or its proposed eight-level/256-item budgets inside authenticator data.
These rules are deferred hardening goals, not current acceptance criteria or
prerequisites for enrollment. The observed library behavior is accepted for now;
it has not been fixed. No fork, custom parser or upstream patch is required for
current work. Retain the characterization tests as evidence for later review.

This exception is limited to opaque authenticator-data internals. Existing outer
IPC, client-data JSON and attestation-object container validation and byte caps
remain enforced. Preserve the library's built-in parsing safeguards and actual
signature/challenge/RP/origin/UP/UV checks, plus Wudo's authorization and replay
rules. The decision does not authorize accepting failed WebAuthn verification.

## Evidence and scope

The isolated experiment directly exercises `webauthn-rs-core` 0.5.5's
`AuthenticatorData::try_from` for authentication and registration. This is a
dev-only dependency already present transitively. Production continues to use
the approved high-level verifier design; no low-level verification API is added.

These fixtures are unsigned structural inputs, not authenticated ceremonies.
Acceptance by this parser does not mean the high-level verifier accepts a
signature, key or action, and does not establish an authentication bypass.

| Deferred Wudo rule / baseline check | Observed parser behavior |
| --- | --- |
| Reject trailing authenticator-data bytes | Accepts bytes after the parsed structure |
| Reject duplicate CBOR map keys | Accepts duplicate extension keys and duplicate COSE integer keys, including equivalent non-shortest encodings |
| Reject indefinite-length CBOR | Accepts an indefinite extension map |
| At most eight nested containers | Accepts ten nested arrays inside an extension map |
| At most 256 decoded inner items | Accepts an extension array with 257 values, plus its enclosing map/key |
| Reject truncated structures | Rejects incomplete fixed header, extension values and unavailable declared credential bytes in tested cases |

All extension fixtures fit inside the 4096-byte assertion authenticator-data
field cap. The COSE fixture is deliberately not a usable public key: it isolates
structural acceptance from later key/algorithm validation.

Source inspection of the pinned dependencies explains the results:

- `webauthn-rs-core/src/internals.rs`: private `cbor_parser` first deserializes
  to `serde_cbor_2::Value`; both COSE and signed extensions use this path.
- `AuthenticatorData::try_from` returns the parsed structure while discarding
  the parser's remaining-input slice.
- `serde_cbor_2` 0.13.0's Value map visitor inserts into a BTreeMap, overwriting
  duplicate keys. Its decoder has its own recursion guard (initialized to 128),
  which is not Wudo's eight-container budget. This is not an unbounded-recursion
  claim or a measured denial-of-service result.

The public parsing entry point has no Wudo-specific budget/strictness argument
and does not expose original COSE/extension spans before Value conversion.
Validating a reserialized parsed object cannot recover duplicates, indefinite
encodings or ignored trailing bytes. A successful size-bounded outer CBOR scan
does not inspect the nested authenticator-data byte string.

## Possible later work

If revisited, prefer a scoped upstream change exposing raw spans or strict
validation before generic Value conversion. Preserve signed bytes and exercise
the high-level verifier path. Any patch or replacement dependency needs its own
review. No upstream report has been sent. Parser logging must still respect
Wudo's secret-safe logging requirements; that obligation is not deferred.

## Validation and remaining work

Three new characterization tests cover the cases above; the experiment also
retains twelve signed-ceremony/compatibility tests. They intentionally document
current acceptance rather than pretend the behavior is fixed. If a strict parser
is selected, add tests that require rejection through the actual verifier path.
Real-browser/ARM coverage, format diversity and durable credential policy remain
separate work. No runtime enrollment or state migration is enabled by this slice.
