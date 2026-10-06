#!/usr/bin/env python3
"""Build and run the disposable browser enrollment test; requires Docker."""
import pathlib
import subprocess
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    subprocess.run(["docker", "info"], check=True, stdout=subprocess.DEVNULL)
    image = "wudo-browser-e2e:local"
    subprocess.run(["docker", "build", "-f", "tests/browser-e2e/Dockerfile",
                    "-t", image, "."], cwd=ROOT, check=True, timeout=3600)
    name = "wudo-e2e-" + uuid.uuid4().hex
    try:
        subprocess.run([
            "docker", "run", "--rm", "--init", "--name", name,
            "--network", "none", "--add-host", "wudo.test:127.0.0.1",
            "--shm-size", "256m", "--memory", "2g", "--pids-limit", "256",
            "--tmpfs", "/run:mode=755", "--tmpfs", "/var/lib/wudo:mode=700",
            image,
        ], check=True, timeout=240)
    finally:
        subprocess.run(["docker", "rm", "--force", name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.SubprocessError):
        raise SystemExit("Browser E2E failed; check Docker availability and the stage output above.")
