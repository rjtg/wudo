# wudo-ui

Rust/WASM enrollment UI served by `wudo-web`. Uses `wasm-bindgen` and `web-sys`
with generated JavaScript glue, without a frontend application framework.

Build from the repository root:

```text
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129 --locked
python3 scripts/build-ui.py
```

Run WASM adapter tests with Node and the matching installed runner:

```text
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner cargo test -p wudo-ui --target wasm32-unknown-unknown --locked
```

See [browser enrollment](../../docs/browser-enrollment.md) for deployment,
trust boundaries, manual validation and limitations. Build output is ignored;
never commit enrollment tickets, production keys or generated browser state.
