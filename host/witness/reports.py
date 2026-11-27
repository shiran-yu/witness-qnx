"""Signed fleet reports: the fleet service accepts a device's report only with the device key's signature.

A device app (tools/witness-report.c) fetches a one-time challenge, puts it in its report, and has witnessd sign
SHA256("witness:report:" || report) with the TPM-bound device key. The TPM releases that key only in a released
boot state on the enrolled firmware, so a tampered or rolled-back device cannot produce an accepted report.
An unsigned report names no device anyone can trust, so it is only counted as rejected.
"""
import json
import os
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .tpm import parse_public

REPORT_LABEL = b"witness:report:"
CHALLENGE_TTL = 60.0  # seconds a challenge stays valid
MAX_CHALLENGES = 4096
MAX_REPORT = 960  # agent/witness-report.h REPORT_MAX


class ReportDesk:
    def __init__(self, device_keys):
        """device_keys(): {device name: device key TPM2B_PUBLIC hex} for the enrolled devices."""
        self.device_keys = device_keys
        self.lock = threading.Lock()
        self.challenges: dict[str, float] = {}
        self.accepted: dict[str, dict] = {}  # device name -> {"count", "time", "report"}
        self.rejected = {"count": 0, "time": None, "reason": None}

    def challenge(self) -> str:
        nonce = os.urandom(16).hex()
        now = time.time()
        with self.lock:
            if len(self.challenges) >= MAX_CHALLENGES:  # drop expired ones, then the oldest
                self.challenges = {n: t for n, t in self.challenges.items() if now - t < CHALLENGE_TTL}
                while len(self.challenges) >= MAX_CHALLENGES:
                    self.challenges.pop(next(iter(self.challenges)))
            self.challenges[nonce] = now
        return nonce

    def _reject(self, reason: str) -> tuple[int, dict]:
        with self.lock:
            self.rejected = {"count": self.rejected["count"] + 1, "time": time.time(), "reason": reason}
        return 403, {"accepted": False, "reason": reason}

    def submit(self, body: dict) -> tuple[int, dict]:
        text = body.get("report") if isinstance(body, dict) else None
        if not isinstance(text, str) or len(text.encode()) > MAX_REPORT:
            return 400, {"accepted": False, "reason": "expected {report, r, s}"}
        try:
            report = json.loads(text)
            nonce = report["nonce"]
        except (ValueError, KeyError, TypeError):
            return 400, {"accepted": False, "reason": "report is not JSON with a nonce"}
        with self.lock:
            issued = self.challenges.pop(nonce, None) if isinstance(nonce, str) else None
        if issued is None or time.time() - issued > CHALLENGE_TTL:
            return self._reject("unknown, used or expired challenge (replay)")
        if "r" not in body or "s" not in body:
            return self._reject("unsigned: " + str(body.get("error", "no signature")))
        try:
            signature = encode_dss_signature(int(body["r"], 16), int(body["s"], 16))
        except (ValueError, TypeError):
            return self._reject("malformed signature")
        message = REPORT_LABEL + text.encode()
        for name, public in self.device_keys().items():
            try:
                parse_public(bytes.fromhex(public)).key().verify(signature, message, ec.ECDSA(hashes.SHA256()))
            except (InvalidSignature, ValueError):
                continue
            with self.lock:
                count = self.accepted.get(name, {}).get("count", 0) + 1
                self.accepted[name] = {"count": count, "time": time.time(), "report": report}
            return 200, {"accepted": True, "device": name}
        return self._reject("signature matches no enrolled device key")

    def status(self, name: str) -> dict | None:
        with self.lock:
            return dict(self.accepted[name]) if name in self.accepted else None
