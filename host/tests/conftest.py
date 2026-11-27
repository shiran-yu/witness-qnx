"""Shared fixtures (real QNX 8.0 QEMU captures) and builders for synthetic TPM structures."""
import copy
import hashlib
import json
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def good() -> dict:
    """{"nonce": bytes, "attestation": dict} from a known-good boot; a fresh copy per test."""
    data = load("attestation-good.json")
    return {"nonce": bytes.fromhex(data["nonce"]), "attestation": data["attestation"]}


@pytest.fixture
def tampered() -> dict:
    """Boot with "PasswordAuthentication yes" appended to /system/etc/ssh/sshd_config."""
    data = load("attestation-tampered-config.json")
    return {"nonce": bytes.fromhex(data["nonce"]), "attestation": data["attestation"]}


@pytest.fixture
def reference() -> dict:
    return load("reference.json")


@pytest.fixture
def enrollment() -> dict:
    return load("enrollment.json")


def flip(hex_blob: str, index: int, mask: int = 0x01) -> str:
    """Flip bits of one byte in a hex string."""
    raw = bytearray.fromhex(hex_blob)
    raw[index] ^= mask
    return raw.hex()


def tpm2b(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data


def ak_public_blob(key: ec.EllipticCurvePrivateKey) -> bytes:
    """TPM2B_PUBLIC for a restricted ECDSA-SHA256 P-256 signing key, laid out as witnessd's AK."""
    numbers = key.public_key().public_numbers()
    area = (struct.pack(">HHI", 0x0023, 0x000B, 0x00050072) + tpm2b(b"")
            + struct.pack(">HHHHH", 0x0010, 0x0018, 0x000B, 0x0003, 0x0010)
            + tpm2b(numbers.x.to_bytes(32, "big")) + tpm2b(numbers.y.to_bytes(32, "big")))
    return tpm2b(area)


def quote_blob(nonce: bytes, pcrs: dict, selected: list[int], bank: int = 0x000B) -> bytes:
    """TPMS_ATTEST of type quote over `selected` PCRs, as the TPM would build it."""
    select = bytearray(3)
    for i in selected:
        select[i // 8] |= 1 << (i % 8)
    digest = hashlib.sha256(b"".join(bytes.fromhex(pcrs[str(i)]) for i in sorted(selected))).digest()
    return (struct.pack(">IH", 0xFF544347, 0x8018) + tpm2b(b"\x00\x0b" + bytes(32)) + tpm2b(nonce)
            + struct.pack(">QIIBQ", 1234, 1, 2, 1, 0x2024012500120000)
            + struct.pack(">IHB", 1, bank, 3) + bytes(select) + tpm2b(digest))


def signature_blob(key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """TPMT_SIGNATURE (ECDSA, SHA-256) over message."""
    r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return struct.pack(">HH", 0x0018, 0x000B) + tpm2b(r.to_bytes(32, "big")) + tpm2b(s.to_bytes(32, "big"))


def forge(attestation: dict, nonce: bytes, key: ec.EllipticCurvePrivateKey, selected=range(10)) -> dict:
    """Re-sign an attestation's reported PCRs with `key`, quoting only `selected`."""
    forged = copy.deepcopy(attestation)
    quote = quote_blob(nonce, forged["pcrs"], list(selected))
    forged.update(ak_public=ak_public_blob(key).hex(), quote=quote.hex(),
                  signature=signature_blob(key, quote).hex())
    if "certify" in forged.get("device_key", {}):  # the AK also signs the device key certification
        certify = bytes.fromhex(forged["device_key"]["certify"])
        forged["device_key"]["certify_signature"] = signature_blob(key, certify).hex()
    return forged
