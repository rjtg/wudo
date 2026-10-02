#!/usr/bin/env python3
"""Linux deployment smoke test; run after cargo build --workspace --locked.

Usage: python3 scripts/ipc-smoke.py
Prompts through sudo, then uses a private mount namespace and temporary /run and /var/lib.
No accounts are created. Numeric test identities exist only in child processes.
"""
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
DAEMON = ROOT / "target/debug/wudod"
CLI = ROOT / "target/debug/wudo"
REQUEST = bytes.fromhex("a26776657273696f6e01696f7065726174696f6e66737461747573")
REPLY = bytes.fromhex("a36776657273696f6e0166726573756c74626f6b66737461747573657265616479")


def check(condition, message):
    if not condition:
        raise RuntimeError(message)
    print("PASS:", message, flush=True)


def probe(path, uid, gid, allowed):
    # Fork before creating the socket so SO_PEERCRED sees the test identity.
    pid = os.fork()
    if pid == 0:
        try:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(2)
                data = b""
                try:
                    client.connect(path)
                    client.sendall(len(REQUEST).to_bytes(4, "big") + REQUEST)
                    client.shutdown(socket.SHUT_WR)
                    while True:
                        chunk = client.recv(128)
                        if not chunk:
                            break
                        data += chunk
                        if len(data) > 128:
                            raise RuntimeError("oversized response")
                except (PermissionError, ConnectionResetError, BrokenPipeError):
                    if allowed:
                        raise
                expected = len(REPLY).to_bytes(4, "big") + REPLY
                if (allowed and data != expected) or (not allowed and data):
                    raise RuntimeError("unexpected authorization result")
            os._exit(0)
        except Exception as error:
            print("probe failed:", error, file=sys.stderr, flush=True)
            os._exit(1)
    _, status = os.waitpid(pid, 0)
    check(os.waitstatus_to_exitcode(status) == 0,
          f"{path} uid={uid} gid={gid} allowed={allowed}")


def isolated(original_namespace):
    check(os.geteuid() == 0, "root test process")
    check(os.readlink("/proc/self/ns/mnt") != original_namespace,
          "private mount namespace")
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "tmpfs", "/run"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "tmpfs", "/var/lib"], check=True)
    state_directory = Path("/var/lib/wudo")
    state_directory.mkdir(mode=0o700)
    state_directory.chmod(0o700)
    directory = Path("/run/wudo")
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    command = [str(DAEMON), "--web-uid", "61001", "--web-gid", "61001"]
    for stop_signal in (signal.SIGTERM, signal.SIGINT):
        process = subprocess.Popen(command)
        idle = None
        try:
            deadline = time.monotonic() + 3
            while not (directory / "web.sock").exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("daemon did not start")
                time.sleep(0.02)
            for name, mode, gid in [("admin.sock", 0o600, os.getegid()), ("web.sock", 0o660, 61001)]:
                info = (directory / name).stat()
                check(stat.S_ISSOCK(info.st_mode) and stat.S_IMODE(info.st_mode) == mode
                      and info.st_uid == 0 and info.st_gid == gid,
                      f"{name} ownership and permissions")
            result = subprocess.run([str(CLI), "status"], capture_output=True, text=True, timeout=6)
            check(result.returncode == 0 and "Daemon IPC reachable" in result.stdout,
                  "production CLI verifies root daemon")
            if stop_signal == signal.SIGTERM:
                for args in [("init",), ("user", "create", "alice", "--label", "Alice"), ("upgrade",)]:
                    result = subprocess.run([str(CLI), *args], capture_output=True, text=True, timeout=6)
                    check(result.returncode == 0, "administrative CLI " + args[0])
            result = subprocess.run([str(CLI), "user", "show", "alice"], capture_output=True, text=True, timeout=6)
            check(result.returncode == 0 and "Alice" in result.stdout, "persistent user inspection")
            probe("/run/wudo/admin.sock", 0, 0, True)
            probe("/run/wudo/admin.sock", 61001, 61001, False)
            probe("/run/wudo/web.sock", 61001, 61001, True)
            probe("/run/wudo/web.sock", 61002, 61001, False)
            probe("/run/wudo/web.sock", 0, 0, False)
            duplicate = subprocess.run(command, capture_output=True, timeout=3)
            check(duplicate.returncode != 0, "second daemon refuses existing endpoints")
            idle = socket.socket(socket.AF_UNIX)
            idle.connect("/run/wudo/admin.sock")
            time.sleep(0.05)
            process.send_signal(stop_signal)
            check(process.wait(timeout=3) == 0, f"{stop_signal.name} shuts down promptly")
            idle.settimeout(1)
            check(idle.recv(1) == b"", "shutdown closes incomplete connection")
            check(not (directory / "admin.sock").exists()
                  and not (directory / "web.sock").exists(), "shutdown removes owned sockets")
        finally:
            if idle is not None:
                idle.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
    print("Deployment smoke test passed. Host /run and /var/lib were not modified.")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--isolated":
        isolated(sys.argv[2])
    elif len(sys.argv) == 1:
        if not DAEMON.is_file() or not CLI.is_file():
            sys.exit("Run cargo build --workspace --locked first.")
        command = ["unshare", "--mount", "--propagation", "private",
                   sys.executable, str(Path(__file__).resolve()), "--isolated",
                   os.readlink("/proc/self/ns/mnt")]
        if os.geteuid() != 0:
            command.insert(0, "sudo")
        sys.exit(subprocess.call(command))
    else:
        sys.exit("Usage: python3 scripts/ipc-smoke.py")
