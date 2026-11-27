# SPDX-License-Identifier: Apache-2.0
"""Appraise one attestation from witnessd against the image reference and the device enrollment.

Trust chain checked, in order:
  1. the quote is signed by this device's enrolled attestation key and carries our fresh nonce
  2. the reported PCR values are exactly the quoted ones (digest over PCR 0-9)
  3. firmware PCRs 0-3, 5-7 equal the enrolled baseline (OVMF / BIOS has no build-time reference)
  4. PCR 4 equals the value predicted from ifs.bin (UEFI): the whole IFS, measured by firmware
  5. replaying the event log reproduces quoted PCR 8 (and 9), so the log is authentic
  6. every logged event matches the reference: names the exact file that changed, appeared or vanished
"""
import hashlib
from dataclasses import dataclass, field

from .tpm import extend, parse_public, parse_quote, signature_valid, TPM_ALG_SHA256

FIRMWARE_PCRS = [0, 1, 2, 3, 5, 6, 7]


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class Verdict:
    trusted: bool
    checks: list[Check] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)  # named differences, for people
    sealed: str = "unknown"

    def to_dict(self) -> dict:
        return {"trusted": self.trusted, "sealed": self.sealed,
                "checks": [c.__dict__ for c in self.checks], "findings": self.findings}


def parse_eventlog(lines: list[str]) -> list[dict]:
    events = []
    for line in lines:
        parts = line.split(" ", 3)
        if len(parts) == 4:
            events.append({"pcr": int(parts[0]), "sha256": parts[1], "type": parts[2], "path": parts[3]})
    return events


def appraise(attestation: dict, nonce: bytes, reference: dict, enrollment: dict | None) -> Verdict:
    verdict = Verdict(trusted=False, sealed=attestation.get("sealed", "unknown"))
    add = verdict.checks.append

    if "error" in attestation:
        add(Check("agent", False, attestation["error"]))
        return verdict

    key = parse_public(bytes.fromhex(attestation["ak_public"]))
    quote = parse_quote(bytes.fromhex(attestation["quote"]))
    enrolled_key = enrollment and enrollment.get("ak_public")
    if enrolled_key and enrolled_key != attestation["ak_public"]:
        add(Check("attestation key", False, "key differs from the enrolled key: different TPM or replaced device"))
        return verdict
    add(Check("attestation key", True, f"AK {key.fingerprint()}" + ("" if enrolled_key else " (enrolling now)")))

    signed = signature_valid(key, quote.raw, bytes.fromhex(attestation["signature"]))
    add(Check("quote signature", signed, "ECDSA P-256 over TPMS_ATTEST"))
    fresh = quote.extra_data == nonce
    add(Check("freshness", fresh, "quote carries this request's nonce" if fresh else "nonce mismatch: replayed quote"))
    if not (signed and fresh):
        return verdict

    pcrs = {int(k): bytes.fromhex(v) for k, v in attestation["pcrs"].items()}
    quoted = quote.selection.get(TPM_ALG_SHA256, [])
    digest = hashlib.sha256(b"".join(pcrs[i] for i in quoted)).digest() if all(i in pcrs for i in quoted) else b""
    consistent = digest == quote.pcr_digest
    add(Check("PCR values", consistent, f"PCR {quoted[0]}-{quoted[-1]} match the signed digest" if consistent
              else "reported PCRs do not match the quote"))
    if not consistent:
        return verdict

    if "5" in reference["pcr"]:
        ok = pcrs[5].hex() == reference["pcr"]["5"]
        add(Check("boot disk layout (PCR 5)", ok, "GPT partition table is the released disk image's" if ok
                  else "boot disk partition table differs from the release"))
        if not ok:
            verdict.findings.append({"pcr": 5, "kind": "changed", "what": "boot disk GPT partition table"})
    if enrollment and "firmware_pcrs" in enrollment:
        firmware = [i for i in FIRMWARE_PCRS if str(i) not in reference["pcr"]]
        changed = [i for i in firmware if enrollment["firmware_pcrs"].get(str(i)) != pcrs[i].hex()]
        add(Check(f"firmware (PCR {','.join(map(str, firmware))})", not changed,
                  "same firmware and configuration as at enrollment" if not changed
                  else f"firmware state changed in PCR {', '.join(map(str, changed))}"))
        for i in changed:
            verdict.findings.append({"pcr": i, "kind": "firmware", "what": f"PCR {i} differs from enrollment"})

    if "4" in reference["pcr"]:
        ok = pcrs[4].hex() == reference["pcr"]["4"]
        add(Check("boot image (PCR 4)", ok, "IFS is the released ifs.bin (Authenticode, measured by UEFI firmware)"
                  if ok else "the IFS that booted is not the released ifs.bin"))
        if not ok:
            verdict.findings.append({"pcr": 4, "kind": "changed", "what": "IFS boot image (kernel, startup, boot script)",
                                     "expected": reference["ifs_authenticode"], "actual": "unknown (firmware log)"})
    elif enrollment and "pcr4" in enrollment:
        ok = pcrs[4].hex() == enrollment["pcr4"]
        add(Check("boot image (PCR 4)", ok, "same as enrollment (no UEFI reference in this image)"))

    events = parse_eventlog(attestation.get("eventlog", []))
    for pcr in (8, 9):
        replay = bytes(32)
        for event in events:
            if event["pcr"] == pcr:
                replay = extend(replay, bytes.fromhex(event["sha256"]))
        ok = replay == pcrs[pcr]
        add(Check(f"event log (PCR {pcr})", ok, "log replays to the quoted PCR" if ok
                  else "log does not replay to the quoted PCR: log edited or events hidden"))
        if not ok:
            return verdict

    for pcr, label in ((8, "system partition (PCR 8)"), (9, "applications (PCR 9)")):
        expected = reference["events"][str(pcr)]
        actual = [e for e in events if e["pcr"] == pcr]
        before = len(verdict.findings)
        by_path = {e["path"]: e for e in expected}
        for event in actual:
            want = by_path.get(event["path"])
            if want is None:
                verdict.findings.append({"pcr": pcr, "kind": "unexpected", "what": event["path"],
                                         "actual": event["sha256"]})
            elif want["sha256"] != event["sha256"]:
                kind = "missing" if event["type"] == "missing" else "changed"
                verdict.findings.append({"pcr": pcr, "kind": kind, "what": event["path"],
                                         "expected": want["sha256"], "actual": event["sha256"]})
        seen = {e["path"] for e in actual}
        for want in expected:
            if want["path"] not in seen:
                verdict.findings.append({"pcr": pcr, "kind": "not measured", "what": want["path"]})
        ok = pcrs[pcr].hex() == reference["pcr"][str(pcr)] and \
            [e["path"] for e in actual] == [e["path"] for e in expected]
        add(Check(label, ok, f"{len(actual)} measurement(s) match the release" if ok
                  else f"{len(verdict.findings) - before} difference(s) from the release"))

    verdict.trusted = all(c.ok for c in verdict.checks)
    return verdict


def enrollment_from(attestation: dict) -> dict:
    """Trust on first use: record the AK and firmware baseline from a boot known to be good."""
    pcrs = attestation["pcrs"]
    return {"ak_public": attestation["ak_public"],
            "firmware_pcrs": {str(i): pcrs[str(i)] for i in FIRMWARE_PCRS},
            "pcr4": pcrs["4"], "device": attestation.get("device", "")}
