#!/usr/bin/env python3
"""Build the Rust/WASM UI with the pinned matching wasm-bindgen CLI."""
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.2.129"


def main():
    tool = shutil.which("wasm-bindgen")
    if tool is None:
        sys.exit(f"Install the UI build tool: cargo install wasm-bindgen-cli --version {VERSION} --locked")
    version = subprocess.check_output([tool, "--version"], text=True).strip()
    if version != f"wasm-bindgen {VERSION}":
        sys.exit(f"UI build requires wasm-bindgen {VERSION}.")
    subprocess.run(["cargo", "build", "-p", "wudo-ui", "--target", "wasm32-unknown-unknown",
                    "--release", "--locked", "--target-dir", str(ROOT / "target")], cwd=ROOT, check=True)
    subprocess.run([tool, "--target", "web", "--no-typescript", "--out-dir", str(ROOT / "ui/wudo-ui/pkg"),
                    str(ROOT / "target/wasm32-unknown-unknown/release/wudo_ui.wasm")], cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
