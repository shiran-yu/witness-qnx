# SPDX-License-Identifier: Apache-2.0
import socket
import threading
import time

import pytest

from witness.cli import request_attestation
from witness.dashboard import Device, Fleet


def trickling_agent(stop: threading.Event) -> int:
    """A device that sends one byte every 0.2 s and never finishes (round 3 repro)."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()

    def serve():
        connection, _ = server.accept()
        while not stop.is_set():
            try:
                connection.sendall(b" ")
            except OSError:
                return
            time.sleep(0.2)
        connection.close()
    threading.Thread(target=serve, daemon=True).start()
    return server.getsockname()[1]


def test_trickling_device_hits_the_total_deadline():
    stop = threading.Event()
    port = trickling_agent(stop)
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        request_attestation(f"127.0.0.1:{port}", b"\0" * 20, timeout=1.0)
    stop.set()
    assert time.monotonic() - started < 2.0


def test_stale_verdict_drops_its_proof(reference):
    device = Device("ecu-01", "127.0.0.1:1")
    fleet = Fleet(reference, [device], None, interval=1.0)
    device.latest = {"time": time.time() - 60, "state": "trusted", "trusted": True, "sealed": "unsealed",
                     "sealed_proven": True, "chain": [{"title": "Firmware", "status": "pass"}]}
    detail = fleet.detail(device)
    assert detail["state"] == "unreachable" and not detail["trusted"]
    assert detail["sealed"] is None and not detail["sealed_proven"]
    assert {s["status"] for s in detail["latest"]["chain"]} == {"not reached"}


def test_device_without_any_verdict_goes_stale(reference):
    device = Device("ecu-02", "127.0.0.1:1")
    device.since -= 60
    assert Fleet(reference, [device], None, interval=1.0).summary(device)["state"] == "unreachable"


def test_verify_requests_do_not_queue_on_a_busy_device(reference):
    import json, urllib.request
    from http.server import ThreadingHTTPServer
    from witness.dashboard import handler_for
    device = Device("ecu-01", "127.0.0.1:1")
    fleet = Fleet(reference, [device], None, interval=1.0)
    calls = []
    fleet.verify = lambda d: calls.append(d)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(fleet))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}/api/devices/ecu-01/verify"
    with device.lock:  # a verification is in progress
        reply = json.load(urllib.request.urlopen(urllib.request.Request(url, method="POST")))
    server.shutdown()
    assert reply["name"] == "ecu-01" and calls == []
