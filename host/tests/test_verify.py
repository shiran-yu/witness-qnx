"""appraise(): the real good/tampered captures, and attacks built by mutating the good capture."""
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from conftest import ak_public_blob, flip, forge, signature_blob
from witness.verify import appraise, enrollment_from, parse_eventlog

SSHD_CONFIG = "/system/etc/ssh/sshd_config"


def checks(verdict) -> dict:
    return {c.name: c.ok for c in verdict.checks}


def failed(verdict) -> list[str]:
    return [c.name for c in verdict.checks if not c.ok]


def test_good_is_trusted(good, reference, enrollment):
    verdict = appraise(good["attestation"], good["nonce"], reference, enrollment)
    assert verdict.trusted, verdict.to_dict()
    assert verdict.findings == []
    assert failed(verdict) == []
    assert verdict.sealed == "unsealed"
    for name in ("attestation key", "quote signature", "freshness", "PCR values", "boot disk layout (PCR 5)",
                 "firmware (PCR 0,1,2,3,6,7)", "boot image (PCR 4)", "event log (PCR 8)", "event log (PCR 9)",
                 "system partition (PCR 8)", "applications (PCR 9)"):
        assert checks(verdict)[name] is True
    json.dumps(verdict.to_dict())  # serialisable for --json


def test_good_without_enrollment_is_trusted_on_first_use(good, reference):
    verdict = appraise(good["attestation"], good["nonce"], reference, None)
    assert verdict.trusted
    assert "enrolling now" in next(c.detail for c in verdict.checks if c.name == "attestation key")


def test_enrollment_from_good_matches_fixture(good, enrollment):
    assert enrollment_from(good["attestation"]) == enrollment


def test_tampered_config_named(tampered, reference, enrollment):
    verdict = appraise(tampered["attestation"], tampered["nonce"], reference, enrollment)
    assert not verdict.trusted
    expected = next(e["sha256"] for e in reference["events"]["8"] if e["path"] == SSHD_CONFIG)
    actual = next(line.split()[1] for line in tampered["attestation"]["eventlog"] if line.endswith(SSHD_CONFIG))
    assert verdict.findings == [{"pcr": 8, "kind": "changed", "what": SSHD_CONFIG,
                                 "expected": expected, "actual": actual}]
    assert failed(verdict) == ["system partition (PCR 8)"]
    assert verdict.sealed == "locked"


# --- freshness and signature ---

def test_wrong_nonce_fails_freshness(good, reference, enrollment):
    nonce = bytes(len(good["nonce"]))
    verdict = appraise(good["attestation"], nonce, reference, enrollment)
    assert not verdict.trusted
    assert checks(verdict)["freshness"] is False
    assert checks(verdict)["quote signature"] is True


def test_replayed_old_quote_fails_freshness(good, tampered, reference, enrollment):
    # good quote replayed against a later request
    verdict = appraise(good["attestation"], tampered["nonce"], reference, enrollment)
    assert not verdict.trusted and checks(verdict)["freshness"] is False


@pytest.mark.parametrize("field,index", [("quote", 50), ("quote", -1), ("signature", 10), ("signature", -1)])
def test_flipped_byte_fails_signature(good, reference, enrollment, field, index):
    attestation = good["attestation"]
    position = index % (len(attestation[field]) // 2)
    attestation[field] = flip(attestation[field], position)
    verdict = appraise(attestation, good["nonce"], reference, enrollment)
    assert not verdict.trusted
    assert checks(verdict)["quote signature"] is False


def test_every_quote_byte_is_covered(good, reference, enrollment):
    # any single-bit change either breaks parsing (fails closed) or breaks the signature
    original = good["attestation"]["quote"]
    for position in range(len(original) // 2):
        attestation = dict(good["attestation"], quote=flip(original, position))
        try:
            verdict = appraise(attestation, good["nonce"], reference, enrollment)
        except ValueError:
            continue
        assert not verdict.trusted, position
        assert checks(verdict)["quote signature"] is False, position


def test_every_signature_byte_is_covered(good, reference, enrollment):
    original = good["attestation"]["signature"]
    for position in range(len(original) // 2):
        attestation = dict(good["attestation"], signature=flip(original, position))
        verdict = appraise(attestation, good["nonce"], reference, enrollment)
        assert not verdict.trusted, position
        assert checks(verdict)["quote signature"] is False, position


# --- attestation key ---

def test_different_enrolled_key_fails(good, reference, enrollment):
    enrollment["ak_public"] = ak_public_blob(ec.generate_private_key(ec.SECP256R1())).hex()
    verdict = appraise(good["attestation"], good["nonce"], reference, enrollment)
    assert not verdict.trusted
    assert failed(verdict) == ["attestation key"]


def test_quote_forged_with_attacker_key_fails(good, reference, enrollment):
    # attacker reports good PCRs but signs with a key outside the device TPM
    attacker = ec.generate_private_key(ec.SECP256R1())
    forged = forge(good["attestation"], good["nonce"], attacker)
    verdict = appraise(forged, good["nonce"], reference, enrollment)
    assert not verdict.trusted and failed(verdict) == ["attestation key"]
    # keeping the enrolled AK blob but signing with the attacker key breaks the signature
    forged["ak_public"] = enrollment["ak_public"]
    verdict = appraise(forged, good["nonce"], reference, enrollment)
    assert not verdict.trusted and checks(verdict)["quote signature"] is False


# --- quote must cover every PCR the verdict relies on ---

@pytest.fixture
def own_ak(good, enrollment):
    """A device AK we hold the private part of, enrolled like the real one."""
    key = ec.generate_private_key(ec.SECP256R1())
    enrollment["ak_public"] = ak_public_blob(key).hex()
    return key


def test_forged_full_quote_with_enrolled_key_is_trusted(good, reference, enrollment, own_ak):
    # positive control for the builders below
    attestation = forge(good["attestation"], good["nonce"], own_ak)
    verdict = appraise(attestation, good["nonce"], reference, enrollment)
    assert verdict.trusted, verdict.to_dict()


def test_quote_not_covering_pcr8_9_fails(good, tampered, reference, enrollment, own_ak):
    # compromised device quotes PCR 0-7 only, then pastes PCR 8/9 and the log from an old good boot
    attestation = forge(tampered["attestation"], tampered["nonce"], own_ak, selected=range(8))
    attestation["pcrs"]["8"] = good["attestation"]["pcrs"]["8"]
    attestation["eventlog"] = good["attestation"]["eventlog"]
    verdict = appraise(attestation, tampered["nonce"], reference, enrollment)
    assert not verdict.trusted
    assert checks(verdict)["PCR values"] is False


def test_empty_pcr_selection_fails(good, reference, enrollment, own_ak):
    attestation = forge(good["attestation"], good["nonce"], own_ak, selected=[])
    verdict = appraise(attestation, good["nonce"], reference, enrollment)
    assert not verdict.trusted
    assert checks(verdict)["PCR values"] is False


# --- reported PCR values ---

@pytest.mark.parametrize("pcr", ["0", "4", "8", "9"])
def test_reported_pcr_changed_fails(good, reference, enrollment, pcr):
    attestation = good["attestation"]
    attestation["pcrs"][pcr] = flip(attestation["pcrs"][pcr], 0)
    verdict = appraise(attestation, good["nonce"], reference, enrollment)
    assert not verdict.trusted
    assert checks(verdict)["PCR values"] is False


def test_reported_pcr_missing_fails(good, reference, enrollment):
    attestation = good["attestation"]
    del attestation["pcrs"]["8"]
    verdict = appraise(attestation, good["nonce"], reference, enrollment)
    assert not verdict.trusted and checks(verdict)["PCR values"] is False


# --- event log cannot be edited ---

def pcr8_lines(attestation) -> list[int]:
    return [i for i, line in enumerate(attestation["eventlog"]) if line.startswith("8 ")]


@pytest.mark.parametrize("which", [0, 1, -1])
def test_eventlog_line_removed_fails(good, reference, enrollment, which):
    attestation = good["attestation"]
    del attestation["eventlog"][pcr8_lines(attestation)[which]]
    verdict = appraise(attestation, good["nonce"], reference, enrollment)
    assert not verdict.trusted
    assert checks(verdict)["event log (PCR 8)"] is False


def test_eventlog_pcr9_line_removed_fails(good, reference, enrollment):
    attestation = good["attestation"]
    attestation["eventlog"] = [line for line in attestation["eventlog"] if not line.startswith("9 ")]
    verdict = appraise(attestation, good["nonce"], reference, enrollment)
    assert not verdict.trusted
    assert checks(verdict)["event log (PCR 8)"] is True
    assert checks(verdict)["event log (PCR 9)"] is False


def test_eventlog_reordered_fails(good, reference, enrollment):
    attestation = good["attestation"]
    first, second = pcr8_lines(attestation)[:2]
    log = attestation["eventlog"]
    log[first], log[second] = log[second], log[first]
    verdict = appraise(attestation, good["nonce"], reference, enrollment)
    assert not verdict.trusted
    assert checks(verdict)["event log (PCR 8)"] is False


def test_eventlog_digest_edited_fails(good, reference, enrollment):
    attestation = good["attestation"]
    index = pcr8_lines(attestation)[2]
    pcr, digest, rest = attestation["eventlog"][index].split(" ", 2)
    attestation["eventlog"][index] = " ".join([pcr, flip(digest, 0), rest])
    verdict = appraise(attestation, good["nonce"], reference, enrollment)
    assert not verdict.trusted
    assert checks(verdict)["event log (PCR 8)"] is False


def test_tampered_log_cannot_hide_change(tampered, reference, enrollment):
    # rewrite the changed file's line to the release digest: replay no longer matches the quote
    attestation = tampered["attestation"]
    release = next(e["sha256"] for e in reference["events"]["8"] if e["path"] == SSHD_CONFIG)
    attestation["eventlog"] = [f"8 {release} file {SSHD_CONFIG}" if line.endswith(SSHD_CONFIG) else line
                               for line in attestation["eventlog"]]
    verdict = appraise(attestation, tampered["nonce"], reference, enrollment)
    assert not verdict.trusted
    assert checks(verdict)["event log (PCR 8)"] is False


def test_parse_eventlog_keeps_spaces_in_path():
    events = parse_eventlog(["8 " + "ab" * 32 + " file /system/my file", "garbage"])
    assert events == [{"pcr": 8, "sha256": "ab" * 32, "type": "file", "path": "/system/my file"}]


# --- agent errors and reference/enrollment mismatches ---

def test_agent_error_is_untrusted(reference, enrollment):
    verdict = appraise({"error": "TPM2_Quote failed: 0x101"}, b"\0" * 20, reference, enrollment)
    assert not verdict.trusted
    assert failed(verdict) == ["agent"]
    assert verdict.checks[0].detail == "TPM2_Quote failed: 0x101"


def test_firmware_change_named(good, reference, enrollment):
    enrollment["firmware_pcrs"]["0"] = "00" * 32
    verdict = appraise(good["attestation"], good["nonce"], reference, enrollment)
    assert not verdict.trusted
    assert failed(verdict) == ["firmware (PCR 0,1,2,3,6,7)"]
    assert verdict.findings == [{"pcr": 0, "kind": "firmware", "what": "PCR 0 differs from enrollment"}]


def test_boot_image_mismatch_named(good, reference, enrollment):
    reference["pcr"]["4"] = "00" * 32
    verdict = appraise(good["attestation"], good["nonce"], reference, enrollment)
    assert not verdict.trusted
    assert failed(verdict) == ["boot image (PCR 4)"]
    assert [(f["pcr"], f["kind"]) for f in verdict.findings] == [(4, "changed")]


def test_boot_disk_mismatch_named(good, reference, enrollment):
    reference["pcr"]["5"] = "00" * 32
    verdict = appraise(good["attestation"], good["nonce"], reference, enrollment)
    assert not verdict.trusted
    assert failed(verdict) == ["boot disk layout (PCR 5)"]
    assert [(f["pcr"], f["kind"]) for f in verdict.findings] == [(5, "changed")]


def test_unexpected_and_unmeasured_files_named(good, reference, enrollment):
    # a reference without sshd but expecting another file: one unexpected, one not measured
    events = reference["events"]["8"]
    sshd = next(e for e in events if e["path"] == "/system/bin/sshd")
    sshd["path"] = "/system/bin/other"
    verdict = appraise(good["attestation"], good["nonce"], reference, enrollment)
    assert not verdict.trusted
    assert failed(verdict) == ["system partition (PCR 8)"]
    kinds = {(f["kind"], f["what"]) for f in verdict.findings}
    assert kinds == {("unexpected", "/system/bin/sshd"), ("not measured", "/system/bin/other")}


def test_signature_blob_builder_matches_real_layout(good):
    # the synthetic TPMT_SIGNATURE has the same header and length as the captured one
    blob = signature_blob(ec.generate_private_key(ec.SECP256R1()), b"x")
    real = bytes.fromhex(good["attestation"]["signature"])
    assert blob[:6] == real[:6] and len(blob) == len(real)
