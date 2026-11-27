# SPDX-License-Identifier: Apache-2.0
"""Signed fleet reports: the fleet service accepts a device's report only with the device key's signature.

A device app (tools/witness-report.c) fetches a one-time challenge, puts it in its report, and has witnessd sign
SHA256("witness:report:" || report) with the TPM-bound device key. The TPM releases that key only in a released
boot state on the enrolled firmware, so a tampered or rolled-back device cannot produce an accepted report.
An unsigned report names no device anyone can trust, so it is only counted as rejected.
Challenges are stateless (random || time || HMAC), so a flood of challenge requests evicts nothing; only
challenges that came back in a report are remembered, until they expire.
"""
import hashlib
import hmac
import json
import os
import struct
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .tpm import parse_public

REPORT_LABEL = b"witness:report:"
CHALLENGE_TTL = 60.0  # seconds a challenge stays valid
MAX_REPORT = 960  # agent/witness-report.h REPORT_MAX
# rejection categories: fixed text, never echoed from the network (shown on the dashboard)
REASONS = {"replay": "unknown, used or expired challenge (replay)",
           "unsigned": "unsigned: the device key was not available to sign",
           "malformed": "malformed signature",
           "unknown-key": "signature matches no enrolled device key"}


class ReportDesk:
    def __init__(self, device_keys):
        """device_keys(): {device name: device key TPM2B_PUBLIC hex} for the enrolled devices."""
        self.device_keys = device_keys
        self.secret = os.urandom(32)
        self.lock = threading.Lock()
        self.used: dict[str, float] = {}  # challenges already submitted -> issue time
        self.accepted: dict[str, dict] = {}  # device name -> {"count", "time", "report"}
        self.rejected = {"count": 0, "time": None, "reason": None}

    def _mac(self, body: bytes) -> bytes:
        return hmac.new(self.secret, body, hashlib.sha256).digest()[:16]

    def challenge(self) -> str:
        body = os.urandom(8) + struct.pack(">d", time.time())
        return (body + self._mac(body)).hex()  # 32 bytes, 64 hex characters

    def _issued(self, nonce) -> float | None:
        """Issue time of a genuine, unexpired challenge, or None."""
        try:
            raw = bytes.fromhex(nonce)
        except (TypeError, ValueError):
            return None
        if len(raw) != 32 or not hmac.compare_digest(raw[16:], self._mac(raw[:16])):
            return None
        issued = struct.unpack(">d", raw[8:16])[0]
        return issued if 0 <= time.time() - issued <= CHALLENGE_TTL else None

    def _reject(self, reason: str) -> tuple[int, dict]:
        with self.lock:
            self.rejected = {"count": self.rejected["count"] + 1, "time": time.time(), "reason": REASONS[reason]}
        return 403, {"accepted": False, "reason": REASONS[reason]}

    def submit(self, body: dict) -> tuple[int, dict]:
        text = body.get("report") if isinstance(body, dict) else None
        try:
            if not isinstance(text, str) or len(text.encode()) > MAX_REPORT:
                return 400, {"accepted": False, "reason": "expected {report, r, s}"}
            report = json.loads(text)
            nonce = report["nonce"]
        except (ValueError, KeyError, TypeError, UnicodeEncodeError):
            return 400, {"accepted": False, "reason": "report is not JSON with a nonce"}
        issued = self._issued(nonce)
        with self.lock:
            now = time.time()
            self.used = {n: t for n, t in self.used.items() if now - t <= CHALLENGE_TTL}
            fresh = issued is not None and nonce not in self.used
        if not fresh:
            return self._reject("replay")
        # the challenge is spent only by a report whose signature verifies, so junk posted first cannot burn it
        if "r" not in body or "s" not in body:
            return self._reject("unsigned")
        try:
            signature = encode_dss_signature(int(body["r"], 16), int(body["s"], 16))
        except (ValueError, TypeError):
            return self._reject("malformed")
        message = REPORT_LABEL + text.encode()
        for name, public in self.device_keys().items():
            try:
                parse_public(bytes.fromhex(public)).key().verify(signature, message, ec.ECDSA(hashes.SHA256()))
            except (InvalidSignature, ValueError):
                continue
            with self.lock:
                spent = nonce in self.used
                if not spent:
                    self.used[nonce] = issued
                    count = self.accepted.get(name, {}).get("count", 0) + 1
                    self.accepted[name] = {"count": count, "time": time.time(), "report": report}
            if spent:
                return self._reject("replay")
            return 200, {"accepted": True, "device": name}
        return self._reject("unknown-key")

    def status(self, name: str) -> dict | None:
        with self.lock:
            return dict(self.accepted[name]) if name in self.accepted else None
