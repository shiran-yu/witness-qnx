# SPDX-License-Identifier: Apache-2.0
"""Fleet dashboard: re-verify each device on a timer and serve the verdicts as a web page and JSON.

  live    challenge each witnessd with a fresh nonce (same path as `witness verify`)
  replay  appraise captured {"nonce","attestation"} files offline with their saved nonces,
          so the page can be shown without QNX or a TPM

Python stdlib only on the server side; the page is witness/static/ (no external assets).
"""
import collections
import glob
import json
import os
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .tpm import parse_public, parse_quote
from .reports import ReportDesk
from .verify import FIRMWARE_PCRS, appraise, parse_eventlog

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
                 ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml"}
HISTORY = 48  # verdicts kept per device

# Trust chain shown on the page, in boot order; each step collects the appraise() checks it covers.
CHAIN = [
    ("evidence", "Device identity and evidence", None,
     "The quote is signed by this device's attestation key, carries a fresh nonce, and its event log is authentic.",
     ("attestation key", "quote signature", "freshness", "PCR values", "event log", "agent", "evidence")),
    ("firmware", "Firmware", "0-3, 6, 7",
     "UEFI firmware and its configuration are the same as when the device was enrolled.", ("firmware",)),
    ("boot", "Boot image", "4",
     "The QNX IFS (kernel, startup, boot script) is the released ifs.bin, measured by firmware.", ("boot image",)),
    ("disk", "Disk layout", "5",
     "The boot disk partition table is the released disk image's.", ("boot disk layout",)),
    ("system", "System and configuration", "8",
     "Every file on /system and in /etc (/data/var/etc) matches the release.", ("system and /etc",)),
    ("apps", "Applications", "9",
     "Every measured application matches the release.", ("applications",)),
    ("key", "Device key", "0, 2, 4, 5, 7-9",
     "The TPM released the device's own key, which it allows only on this device's firmware and a boot state "
     "the release key signed, and the key signed "
     "this request.", ("device key",)),
]
KIND_TEXT = {
    "changed": "changed since the release",
    "missing": "is missing from the device",
    "unexpected": "was measured but is not in the release",
    "not measured": "is in the release but was never measured",
    "firmware": "firmware state differs from enrollment",
}
PCR_PLACE = {4: "boot image", 5: "disk layout", 8: "system and configuration", 9: "applications"}


def describe(finding: dict) -> dict:
    """One finding in plain language."""
    pcr, kind, what = finding["pcr"], finding["kind"], finding["what"]
    place = PCR_PLACE.get(pcr, "firmware")
    if kind == "firmware":
        title = f"Firmware measurement PCR {pcr} differs from enrollment"
    elif finding.get("older_release"):
        title = f"{what} rolled back to release {finding['older_release']}"
    else:
        title = f"{what} {KIND_TEXT.get(kind, kind)}"
    return dict(finding, title=title, place=f"{place} (PCR {pcr})")


def mark_events(events: list[dict], reference: dict) -> list[dict]:
    """Event log rows, each marked ok / changed / missing / unexpected / not measured against the reference."""
    expected = {pcr: {e["path"]: e for e in reference["events"].get(str(pcr), [])} for pcr in (8, 9)}
    rows, seen = [], {8: set(), 9: set()}
    for index, event in enumerate(events, 1):
        row = dict(event, index=index, expected=None)
        want = expected.get(event["pcr"], {}).get(event["path"])
        if event["pcr"] not in expected:
            row["status"] = "info"
        elif want is None:
            row["status"] = "unexpected"
        else:
            seen[event["pcr"]].add(event["path"])
            row["expected"] = want["sha256"]
            if want["sha256"] == event["sha256"]:
                row["status"] = "ok"
            else:
                row["status"] = "missing" if event["type"] == "missing" else "changed"
        rows.append(row)
    for pcr in (8, 9):
        for path, want in expected[pcr].items():
            if path not in seen[pcr]:
                rows.append({"index": None, "pcr": pcr, "type": want["type"], "path": path, "sha256": None,
                             "expected": want["sha256"], "status": "not measured"})
    return rows


def pcr_table(pcrs: dict, reference: dict, enrollment: dict | None) -> list[dict]:
    rows = []
    for i in range(10):
        actual = pcrs.get(str(i))
        if str(i) in reference["pcr"]:
            expected, source = reference["pcr"][str(i)], "release"
        elif enrollment and i in FIRMWARE_PCRS:
            expected, source = enrollment.get("firmware_pcrs", {}).get(str(i)), "enrollment"
        else:
            expected, source = None, "not appraised"
        status = "info" if expected is None else ("ok" if actual == expected else "changed")
        rows.append({"pcr": i, "actual": actual, "expected": expected, "source": source, "status": status})
    return rows


def chain_steps(checks: list[dict], enrolled: bool, findings: list[dict] = ()) -> list[dict]:
    step_pcrs = {"firmware": FIRMWARE_PCRS, "boot": [4], "disk": [5], "system": [8], "apps": [9]}
    steps = []
    for key, title, pcrs, explain, prefixes in CHAIN:
        mine = [c for c in checks if c["name"].startswith(prefixes)]
        if mine:
            status = "pass" if all(c["ok"] for c in mine) else "fail"
            detail = "; ".join(c["detail"] for c in mine if not c["ok"]) or \
                (mine[0]["detail"] if len(mine) == 1 else f"all {len(mine)} checks passed")
            named = [f["title"] for f in findings if (f["kind"] == "firmware") == (key == "firmware")
                     and f["pcr"] in step_pcrs.get(key, [])]
            if status == "fail" and named:
                detail += ": " + "; ".join(named[:3]) + (f" and {len(named) - 3} more" if len(named) > 3 else "")
            if key == "firmware" and "(PCR " in mine[0]["name"]:
                pcrs = mine[0]["name"].split("(PCR ")[1].rstrip(")").replace(",", ", ")
            if key == "key" and "signed release" not in mine[0]["name"]:  # image built without a release key
                explain = ("The TPM released the device's own key, which it allows only in the boot state the device "
                           "was provisioned in (PolicyPCR), and the key signed this request.")
        elif key == "firmware" and not enrolled:
            status, detail = "skipped", "Not enrolled: run `witness enroll` on a known-good boot to record the firmware baseline."
        else:
            status, detail = "not reached", "Not checked: an earlier step failed."
        if status != "pass":  # the step text is the condition; it holds only for a passed step
            explain = "Required: " + (explain[0].lower() if explain[1:2].islower() else explain[0]) + explain[1:]
        steps.append({"key": key, "title": title, "pcrs": pcrs, "explain": explain, "status": status,
                      "detail": detail, "checks": mine})
    return steps


class Device:
    def __init__(self, name: str, address: str | None = None, evidence: str | None = None):
        self.name, self.address, self.evidence = name, address, evidence
        self.lock = threading.Lock()  # one verification at a time per device
        self.latest: dict | None = None
        self.since = time.time()  # staleness baseline before the first verdict
        self.history = collections.deque(maxlen=HISTORY)


class Fleet:
    def __init__(self, reference: dict, devices: list[Device], state: str | None, enrollment: dict | None = None,
                 environment: str | None = None, interval: float = 10.0):
        self.reference, self.devices, self.state = reference, {d.name: d for d in devices}, state
        self.fixed_enrollment, self.environment, self.interval = enrollment, environment, interval
        self.mode = "replay" if all(d.evidence for d in devices) else "live"
        self.reports = ReportDesk(self.device_keys)

    def device_keys(self) -> dict:
        """Enrolled device key per device: the only keys a signed fleet report may carry."""
        keys = {}
        for device in self.devices.values():
            key = (self.enrollment(device) or {}).get("device_key")
            if key:
                keys[device.name] = key
        return keys

    def enrollment(self, device: Device) -> dict | None:
        if device.evidence:
            return self.fixed_enrollment
        from .cli import enrollment_path
        path = enrollment_path(self.state, device.address)
        return json.load(open(path)) if os.path.exists(path) else None

    def collect(self, device: Device) -> tuple[dict, bytes]:
        if device.evidence:
            saved = json.load(open(device.evidence))
            return saved["attestation"], bytes.fromhex(saved["nonce"])
        from .cli import request_attestation
        nonce = os.urandom(20)
        return request_attestation(device.address, nonce, timeout=min(20.0, max(5.0, self.interval))), nonce

    def verify(self, device: Device) -> dict:
        with device.lock:
            started = time.time()
            enrollment = self.enrollment(device)
            result = {"time": started, "enrolled": enrollment is not None}
            try:
                attestation, nonce = self.collect(device)
            except (OSError, ValueError) as error:
                result.update(state="unreachable", trusted=False, error=f"no answer from witnessd: {error}",
                              checks=[], findings=[], chain=chain_steps([], enrollment is not None))
            else:
                try:
                    result.update(self.appraise(attestation, nonce, enrollment))
                except Exception as error:  # anything unexpected in the evidence fails closed, never keeps the old state
                    result.update(state="not trusted", trusted=False, checks=[{"name": "evidence", "ok": False,
                                  "detail": f"malformed attestation: {error!r}"}], findings=[],
                                  chain=chain_steps([], enrollment is not None))
            result["duration_ms"] = round((time.time() - started) * 1000)
            device.latest = result
            device.history.append({"time": started, "state": result["state"],
                                   "findings": [f["title"] for f in result["findings"]][:3]})
            return result

    def appraise(self, attestation: dict, nonce: bytes, enrollment: dict | None) -> dict:
        try:
            verdict = appraise(attestation, nonce, self.reference, enrollment).to_dict()
        except (KeyError, ValueError, TypeError) as error:
            verdict = {"trusted": False, "sealed": attestation.get("sealed", "unknown"),
                       "checks": [{"name": "evidence", "ok": False, "detail": f"malformed attestation: {error}"}],
                       "findings": []}
        findings = [describe(f) for f in verdict["findings"]]
        result = {"state": "trusted" if verdict["trusted"] else "not trusted", "trusted": verdict["trusted"],
                  "sealed": verdict["sealed"], "sealed_proven": verdict.get("sealed_proven", False),
                  "checks": verdict["checks"], "findings": findings,
                  "chain": chain_steps(verdict["checks"], enrollment is not None, findings),
                  "agent_device": attestation.get("device")}
        try:
            result["ak_fingerprint"] = parse_public(bytes.fromhex(attestation["ak_public"])).fingerprint()
            quote = parse_quote(bytes.fromhex(attestation["quote"]))
            result["quote"] = {"clock_ms": quote.clock, "reset_count": quote.reset_count,
                               "restart_count": quote.restart_count, "firmware_version": f"{quote.firmware_version:016x}"}
        except (KeyError, ValueError):
            pass
        if isinstance(attestation.get("pcrs"), dict):
            result["pcrs"] = pcr_table(attestation["pcrs"], self.reference, enrollment)
        if isinstance(attestation.get("eventlog"), list):
            result["events"] = mark_events(parse_eventlog(attestation["eventlog"]), self.reference)
        return result

    def summary(self, device: Device) -> dict:
        latest = device.latest or {}
        state, error = latest.get("state", "checking"), latest.get("error")
        age = time.time() - latest.get("time", device.since)
        stale = age > max(3 * self.interval, 30)  # a verdict that is not being renewed is not a verdict
        if stale:
            state, error = "unreachable", f"no completed verification for {int(age)} s"
        return {"name": device.name, "address": device.address,
                "evidence": os.path.basename(device.evidence) if device.evidence else None,
                "state": state, "trusted": latest.get("trusted") and state == "trusted",
                "sealed": None if stale else latest.get("sealed"),
                "sealed_proven": not stale and latest.get("sealed_proven", False),
                "ak_fingerprint": latest.get("ak_fingerprint"),
                "enrolled": latest.get("enrolled"), "time": latest.get("time"), "error": error,
                "failed_check": next((f"{c['name']}: {c['detail']}" for c in latest.get("checks", []) if not c["ok"]), None),
                "findings": latest.get("findings", []), "history": list(device.history),
                "reports": self.reports.status(device.name)}

    def detail(self, device: Device) -> dict:
        summary, latest = self.summary(device), device.latest
        if latest and summary["state"] == "unreachable" and latest.get("state") != "unreachable":
            # stale proof is not shown as proof
            latest = dict(latest, chain=[dict(s, status="not reached") for s in latest.get("chain", [])])
        return dict(summary, latest=latest)

    def overview(self) -> dict:
        reference = self.reference
        return {"mode": self.mode, "interval": self.interval, "environment": self.environment, "now": time.time(),
                "reference": {"image": reference.get("image"), "created": reference.get("created"),
                              "boot_mode": reference.get("boot_mode"), "ifs_sha256": reference.get("ifs_sha256")},
                "devices": [self.summary(d) for d in self.devices.values()],
                "reports_rejected": dict(self.reports.rejected)}

    def watch(self, stop: threading.Event) -> None:
        # one loop per device: a hung device must not delay the others
        def loop(device: Device) -> None:
            while not stop.is_set():
                self.verify(device)
                stop.wait(self.interval)
        workers = [threading.Thread(target=loop, args=(d,), daemon=True) for d in self.devices.values()]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()


def handler_for(fleet: Fleet):
    class Handler(BaseHTTPRequestHandler):
        server_version = "witness-dashboard"

        def log_message(self, *args):
            pass

        def send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, status: int, data) -> None:
            self.send(status, json.dumps(data).encode(), "application/json")

        def device(self, parts: list[str]) -> Device | None:
            return fleet.devices.get(urllib.parse.unquote(parts[2])) if len(parts) >= 3 else None

        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            parts = path.strip("/").split("/")
            if path == "/api/devices":
                return self.send_json(200, fleet.overview())
            if path == "/api/report/challenge":
                return self.send_json(200, {"nonce": fleet.reports.challenge()})
            if parts[:2] == ["api", "devices"] and len(parts) == 3:
                device = self.device(parts)
                return self.send_json(200, fleet.detail(device)) if device else self.send_json(404, {"error": "no such device"})
            name = "index.html" if path in ("/", "/index.html") else path[len("/static/"):] if path.startswith("/static/") else None
            if name and "/" not in name and not name.startswith("."):
                file = os.path.join(STATIC, name)
                if os.path.isfile(file):
                    return self.send(200, open(file, "rb").read(),
                                     CONTENT_TYPES.get(os.path.splitext(name)[1], "application/octet-stream"))
            self.send_json(404, {"error": "not found"})

        def do_POST(self):
            parts = urllib.parse.urlparse(self.path).path.strip("/").split("/")
            if parts == ["api", "report"]:  # a device's signed fleet report (witness/reports.py)
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    body = json.loads(self.rfile.read(length)) if 0 < length <= 4096 else None
                except ValueError:
                    body = None
                return self.send_json(*fleet.reports.submit(body))
            if parts[:2] == ["api", "devices"] and len(parts) == 4 and parts[3] == "verify":
                device = self.device(parts)
                if not device:
                    return self.send_json(404, {"error": "no such device"})
                if not device.lock.locked():  # a verification already running answers this request too
                    fleet.verify(device)
                return self.send_json(200, fleet.detail(device))
            self.send_json(404, {"error": "not found"})

    return Handler


def replay_fleet(directory: str, reference_path: str | None, interval: float, environment: str | None) -> Fleet:
    reference = json.load(open(reference_path or os.path.join(directory, "reference.json")))
    enrollment_file = os.path.join(directory, "enrollment.json")
    enrollment = json.load(open(enrollment_file)) if os.path.exists(enrollment_file) else None
    files = sorted(glob.glob(os.path.join(directory, "attestation-*.json")))
    if not files:
        raise SystemExit(f"no attestation-*.json in {directory}")
    devices = [Device(os.path.basename(f)[len("attestation-"):-len(".json")], evidence=f) for f in files]
    return Fleet(reference, devices, None, enrollment=enrollment, interval=interval,
                 environment=environment or "Replay of evidence captured from QNX 8.0 on QEMU with a software TPM (swtpm)")


def live_fleet(reference_path: str, state: str, specs: list[str], interval: float, environment: str | None) -> Fleet:
    devices = []
    for spec in specs:
        name, sep, address = spec.partition("=")
        if not sep:
            name, address = spec, spec
        devices.append(Device(name, address=address))
    return Fleet(json.load(open(reference_path)), devices, state, interval=interval, environment=environment)


def serve(fleet: Fleet, host: str, port: int) -> None:
    stop = threading.Event()
    threading.Thread(target=fleet.watch, args=(stop,), daemon=True).start()
    server = ThreadingHTTPServer((host, port), handler_for(fleet))
    print(f"Witness dashboard ({fleet.mode}, {len(fleet.devices)} device(s)): http://{host}:{port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.server_close()
