"""Signed fleet reports: accepted only with a fresh challenge and the enrolled device key's signature."""
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from conftest import ak_public_blob
from witness.reports import REPORT_LABEL, ReportDesk


def make_desk():
    keys = {name: ec.generate_private_key(ec.SECP256R1()) for name in ("gateway-a", "gateway-b")}
    desk = ReportDesk(lambda: {name: ak_public_blob(key).hex() for name, key in keys.items()})
    return desk, keys


def signed(key, nonce, seq=1, sign_text=None):
    text = json.dumps({"device": "noname", "nonce": nonce, "seq": seq, "uptime_s": 42})
    r, s = decode_dss_signature(key.sign(REPORT_LABEL + (sign_text or text).encode(), ec.ECDSA(hashes.SHA256())))
    return {"report": text, "r": f"{r:064x}", "s": f"{s:064x}"}


def test_signed_report_is_accepted_and_attributed():
    desk, keys = make_desk()
    status, result = desk.submit(signed(keys["gateway-b"], desk.challenge()))
    assert (status, result) == (200, {"accepted": True, "device": "gateway-b"})
    assert desk.status("gateway-b")["count"] == 1 and desk.status("gateway-a") is None


def test_unsigned_report_from_a_locked_device_is_rejected():
    desk, _ = make_desk()
    nonce = desk.challenge()
    body = {"report": json.dumps({"nonce": nonce, "seq": 1}), "error": "device key refused by the TPM (rc 0x99d)"}
    status, result = desk.submit(body)
    assert status == 403 and result["reason"].startswith("unsigned")
    assert "rc 0x99d" not in json.dumps(desk.rejected)  # fixed reasons only, never text from the network
    assert desk.rejected["count"] == 1


def test_replayed_or_invented_challenge_is_rejected():
    desk, keys = make_desk()
    body = signed(keys["gateway-a"], desk.challenge())
    assert desk.submit(body)[0] == 200
    assert desk.submit(body)[0] == 403  # the same challenge twice
    assert desk.submit(signed(keys["gateway-a"], "00" * 16))[0] == 403  # never issued


def test_changed_report_or_foreign_key_is_rejected():
    desk, keys = make_desk()
    nonce = desk.challenge()
    body = signed(keys["gateway-a"], nonce, sign_text=json.dumps({"nonce": nonce, "seq": 999}))  # signed other text
    assert desk.submit(body)[1]["reason"] == "signature matches no enrolled device key"
    stranger = ec.generate_private_key(ec.SECP256R1())
    assert desk.submit(signed(stranger, desk.challenge()))[0] == 403


def test_attestation_signature_is_not_a_report_signature():
    desk, keys = make_desk()
    nonce = desk.challenge()
    text = json.dumps({"nonce": nonce})
    r, s = decode_dss_signature(keys["gateway-a"].sign(b"witness:device-key:" + text.encode(), ec.ECDSA(hashes.SHA256())))
    assert desk.submit({"report": text, "r": f"{r:x}", "s": f"{s:x}"})[0] == 403


def test_challenge_flood_evicts_nothing():
    desk, keys = make_desk()
    nonce = desk.challenge()
    for _ in range(5000):
        desk.challenge()
    assert desk.submit(signed(keys["gateway-a"], nonce))[0] == 200


def test_forged_or_expired_challenge_is_rejected():
    desk, keys = make_desk()
    nonce = desk.challenge()
    forged = nonce[:-2] + ("00" if nonce[-2:] != "00" else "01")
    assert desk.submit(signed(keys["gateway-a"], forged))[0] == 403
    other = ReportDesk(desk.device_keys)  # another server's secret
    assert other.submit(signed(keys["gateway-a"], nonce))[0] == 403


def test_unencodable_report_is_a_clean_400():
    desk, _ = make_desk()
    assert desk.submit({"report": "\ud800"})[0] == 400
