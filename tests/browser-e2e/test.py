"""Container-only test: real browser/UI/HTTPS/IPC, virtual CTAP2 authenticator.

Never invoke this on the host: it provisions disposable container state.
Opt-in debug diagnostics include synthetic enrollment data; never use real credentials here.
"""
import os
from pathlib import Path
import re
import subprocess
import time
import traceback

from playwright.sync_api import expect, sync_playwright

DEBUG = os.environ.get("WUDO_E2E_DEBUG") == "1"
ORIGIN = "https://wudo.test"
children = []
stage = "container prerequisites"
http_statuses = []
create_outcome = "not-called"


def debug(*args, **kwargs):
    if DEBUG:
        print(*args, **kwargs)


def check(condition, label):
    if not condition:
        raise RuntimeError(label)
    print("PASS:", label, flush=True)


def command(args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15, **kwargs)
    if result.returncode:
        raise RuntimeError(f"Command {args!r} exited {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    return result.stdout


def cli(*args):
    output = command(["wudo", *args])
    if args != ("status",):
        debug("CLI:", args, "\n" + output, flush=True)
    return output


def start(args, **kwargs):
    process = subprocess.Popen(args, **kwargs)
    children.append(process)
    return process


def daemon():
    process = start(["wudod", "--web-uid", "61001", "--web-gid", "61001"])
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        try:
            cli("status")
            return process
        except RuntimeError:
            time.sleep(0.1)
    raise RuntimeError("daemon readiness")


def field(output, label):
    match = re.search(r"^" + re.escape(label) + r": ([0-9a-f]+)$", output, re.MULTILINE)
    if not match:
        raise RuntimeError(f"Expected field {label!r} missing from {output!r}")
    return match[1]


def main():
    global stage
    check(Path("/.dockerenv").exists() and os.geteuid() == 0, "disposable root container")
    Path("/run/wudo").mkdir(mode=0o755)
    Path("/var/lib/wudo").chmod(0o700)
    # Trust a fresh test CA in Chromium's container-local NSS database. No TLS bypass.
    tls = Path("/tmp/wudo-tls")
    tls.mkdir(mode=0o700)
    command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(tls / "ca.key"), "-out", str(tls / "ca.crt"),
             "-days", "1", "-subj", "/CN=Wudo E2E CA",
             "-addext", "basicConstraints=critical,CA:TRUE"])
    command(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(tls / "server.key"), "-out", str(tls / "server.csr"),
             "-subj", "/CN=wudo.test"])
    (tls / "extensions").write_text("subjectAltName=DNS:wudo.test\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
    command(["openssl", "x509", "-req", "-in", str(tls / "server.csr"),
             "-CA", str(tls / "ca.crt"), "-CAkey", str(tls / "ca.key"),
             "-CAcreateserial", "-out", str(tls / "server.crt"), "-days", "1",
             "-extfile", str(tls / "extensions")])
    nss = Path.home() / ".pki/nssdb"
    nss.mkdir(parents=True, exist_ok=True)
    command(["certutil", "-N", "--empty-password", "-d", "sql:" + str(nss)])
    command(["certutil", "-A", "-d", "sql:" + str(nss), "-n", "Wudo E2E CA",
             "-t", "C,,", "-i", str(tls / "ca.crt")])
    config = Path("/tmp/nginx.conf")
    config.write_text("""error_log stderr;
pid /run/nginx.pid;
events {}
http {
  access_log off;
  server {
    listen 127.0.0.1:443 ssl;
    server_name wudo.test;
    ssl_certificate /tmp/wudo-tls/server.crt;
    ssl_certificate_key /tmp/wudo-tls/server.key;
    location / {
      proxy_pass http://127.0.0.1:8080;
      proxy_set_header Host $http_host;
    }
  }
}
""")
    stage = "daemon and service startup"
    service = daemon()
    cli("init", "--origin", ORIGIN)
    cli("user", "create", "alice", "--label", "Alice")
    web = start(["wudo-web", "--origin", ORIGIN, "--assets", "/opt/wudo-ui"],
                user=61001, group=61001, extra_groups=[])
    proxy = start(["nginx", "-c", str(config), "-g", "daemon off;"])
    with sync_playwright() as playwright:
        stage = "Chromium and trusted HTTPS/UI readiness"
        browser = playwright.chromium.launch()
        context = browser.new_context(ignore_https_errors=False)
        def report_create(outcome):
            global create_outcome
            if outcome in {"pending", "returned", "NotAllowedError", "NotSupportedError",
                           "SecurityError", "InvalidStateError", "TypeError", "AbortError", "other-error",
                           "client-data-extra-fields", "client-data-standard-fields"}:
                create_outcome = outcome
                debug("Browser credential creation:", outcome, flush=True)
        context.expose_function("e2eReportCreate", report_create)
        def report_shape(shape):
            # Whitelist names and scalar types; no arbitrary browser text.
            flags = {"credentialClass", "responseClass", "createType", "challengeString",
                     "originString", "crossOriginFalse", "topOriginPresent", "tokenBindingPresent"}
            sizes = {"credentialBytes", "clientDataBytes", "attestationBytes"}
            if isinstance(shape, dict):
                safe = {key: value for key, value in shape.items()
                        if (key in flags and type(value) is bool)
                        or (key in sizes and type(value) is int and 0 <= value <= 65536)}
                debug("Browser response shape:", safe, flush=True)
        context.expose_function("e2eReportShape", report_shape)
        # Test-only observation; the credential returned to the app is unchanged.
        context.add_init_script("""(() => {
          window.e2eCreateOutcome = 'not-called';
          const original = navigator.credentials.create.bind(navigator.credentials);
          navigator.credentials.create = async (...args) => {
            window.e2eCreateOutcome = 'pending';
            void window.e2eReportCreate('pending');
            try {
              const result = await original(...args);
              // Report only whether our current strict field allowlist matches.
              // Original signed bytes are never rewritten. Debug logs use synthetic data only.
              const data = JSON.parse(new TextDecoder().decode(result.response.clientDataJSON));
              if (__E2E_DEBUG__) console.log("Synthetic clientDataJSON:", JSON.stringify(data));
              void window.e2eReportShape({
                credentialClass: result instanceof PublicKeyCredential,
                responseClass: result.response instanceof AuthenticatorAttestationResponse,
                credentialBytes: result.rawId.byteLength,
                clientDataBytes: result.response.clientDataJSON.byteLength,
                attestationBytes: result.response.attestationObject.byteLength,
                createType: data.type === 'webauthn.create',
                challengeString: typeof data.challenge === 'string',
                originString: typeof data.origin === 'string',
                crossOriginFalse: data.crossOrigin === undefined || data.crossOrigin === false,
                topOriginPresent: Object.hasOwn(data, 'topOrigin'),
                tokenBindingPresent: Object.hasOwn(data, 'tokenBinding'),
              });
              const known = ['type', 'challenge', 'origin', 'crossOrigin'];
              void window.e2eReportCreate(Object.keys(data).some(key => !known.includes(key))
                ? 'client-data-extra-fields' : 'client-data-standard-fields');
              window.e2eCreateOutcome = 'returned';
              void window.e2eReportCreate('returned');
              return result;
            } catch (error) {
              const allowed = ['NotAllowedError', 'NotSupportedError', 'SecurityError',
                               'InvalidStateError', 'TypeError', 'AbortError'];
              window.e2eCreateOutcome = allowed.includes(error.name) ? error.name : 'other-error';
              void window.e2eReportCreate(window.e2eCreateOutcome);
              throw error;
            }
          };
        })();""".replace("__E2E_DEBUG__", "true" if DEBUG else "false"))
        page = context.new_page()
        page.on("pageerror", lambda error: debug("Browser exception:", error, flush=True))
        page.on("console", lambda message: debug(f"Browser {message.type}: {message.text}", flush=True))
        page.on("requestfailed", lambda request: debug("Failed request:", request.url, request.failure, flush=True))
        def log_response(response):
            if response.url == ORIGIN + "/api/enroll":
                try:
                    body = response.body()
                    debug("Enrollment response:", response.status, response.headers,
                          "CBOR hex:", body[:65536].hex(), flush=True)
                except Exception as error:
                    debug("Response diagnostic failed:", error, flush=True)
        if DEBUG:
            page.on("response", log_response)
        page.on("response", lambda response: http_statuses.append(response.status)
                if response.url == ORIGIN + "/api/enroll" else None)
        page.set_default_timeout(15000)
        deadline = time.monotonic() + 15
        while True:
            try:
                page.goto(ORIGIN, timeout=3000)
                page.locator("#enroll:enabled").wait_for()
                break
            except Exception:
                if time.monotonic() >= deadline or web.poll() is not None or proxy.poll() is not None:
                    raise RuntimeError("HTTPS/UI readiness") from None
                time.sleep(0.1)
        check(page.evaluate("window.isSecureContext"), "trusted HTTPS and loaded WASM UI")
        cdp = context.new_cdp_session(page)
        cdp.send("WebAuthn.enable", {"enableUI": False})
        authenticator_options = {
            "protocol": "ctap2", "ctap2Version": "ctap2_1",
            "transport": "usb", "hasResidentKey": True,
            "hasUserVerification": True, "isUserVerified": True,
            "automaticPresenceSimulation": True,
        }
        authenticator = cdp.send("WebAuthn.addVirtualAuthenticator",
                                 {"options": authenticator_options})["authenticatorId"]
        stage = "code-based browser registration"
        opened = cli("enroll", "alice")
        enrollment = field(opened, "Enrollment")
        ticket = field(opened, "Ticket (transfer privately to the Wudo UI; never put it in a URL)")
        page.locator("#ticket").fill(ticket)
        del ticket, opened
        page.locator("#enroll").click()
        stage = "waiting for registration UI outcome"
        expect(page.locator("#status")).to_have_text(
            re.compile(r".*must inspect and approve.*|Enrollment did not complete.*"), timeout=15000)
        if page.locator("#status").inner_text().startswith("Enrollment did not complete"):
            debug("UI displayed credential identity:", bool(page.locator("#identity").inner_text()), flush=True)
            raise RuntimeError("UI rejected registration")
        check(True, "browser registration reached pending approval")
        stage = "reading browser credential identity"
        credential = field(page.locator("#identity").inner_text(), "Credential ID")
        stage = "checking pending credential is not stored"
        check("No credentials" in cli("credential", "list", "alice"), "pending registration is not active")
        stage = "local approval"
        candidate = field(cli("enroll", "inspect", enrollment), "Candidate")
        cli("enroll", "approve", enrollment, candidate)
        check("State: active" in cli("credential", "show", "alice", credential), "local approval activates exact browser credential")
        stage = "daemon restart and persistence"
        service.terminate()
        service.wait(timeout=10)
        service = daemon()
        check("State: active" in cli("credential", "show", "alice", credential), "credential persists across daemon restart")

        stage = "cancelled enrollment rejection"
        opened = cli("enroll", "alice")
        cli("enroll", "cancel", field(opened, "Enrollment"))
        page.reload()
        page.locator("#ticket").fill(field(opened, "Ticket (transfer privately to the Wudo UI; never put it in a URL)"))
        del opened
        page.locator("#enroll:enabled").click()
        expect(page.locator("#status")).to_have_text(re.compile(r"Enrollment did not complete.*"), timeout=15000)
        check(page.locator("#identity").inner_text() == "", "cancelled ticket cannot create a candidate")
        check(cli("credential", "list", "alice").count("\tactive") == 1,
              "cancelled enrollment leaves stored credentials unchanged")

        stage = "explicit insecure browser registration"
        # A second credential for this user needs a different authenticator:
        # the first device correctly matches the daemon's excludeCredentials.
        cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": authenticator})
        cdp.send("WebAuthn.addVirtualAuthenticator", {"options": authenticator_options})
        cli("enroll", "alice", "--insecure")
        page.reload()
        page.locator("#insecure").check()
        page.locator("#enroll:enabled").click()
        expect(page.locator("#status")).to_have_text(re.compile(r"Passkey enrolled\..*"), timeout=15000)
        second = field(page.locator("#identity").inner_text(), "Credential ID")
        check(second != credential and "State: active" in cli("credential", "show", "alice", second), "explicit insecure enrollment activates a new credential")
        browser.close()
    print("Browser enrollment E2E passed.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        debug("Enrollment HTTP status codes:", http_statuses[:8])
        debug("Last browser credential outcome:", create_outcome)
        if DEBUG:
            traceback.print_exc()
        else:
            print("Rerun scripts/browser-e2e.py --debug for detailed diagnostics.")
        raise SystemExit("FAIL: " + stage) from None
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
