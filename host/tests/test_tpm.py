"""TPM structure parsing, quote signature check and PCR extend."""
import hashlib
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from conftest import ak_public_blob, flip, quote_blob, signature_blob
from witness import tpm


def test_parse_public_fixture(good):
    blob = bytes.fromhex(good["attestation"]["ak_public"])
    key = tpm.parse_public(blob)
    assert key.curve == tpm.TPM_ECC_NIST_P256
    assert len(key.x) == len(key.y) == 32
    area = blob[2:]
    assert key.name == b"\x00\x0b" + hashlib.sha256(area).digest()
    assert key.fingerprint() == hashlib.sha256(key.x + key.y).hexdigest()[:16]
    numbers = key.key().public_numbers()
    assert numbers.x == int.from_bytes(key.x, "big") and numbers.y == int.from_bytes(key.y, "big")


def test_parse_public_roundtrip_generated_key():
    private = ec.generate_private_key(ec.SECP256R1())
    key = tpm.parse_public(ak_public_blob(private))
    assert key.key().public_numbers() == private.public_key().public_numbers()


def test_parse_public_rejects_non_ecc_and_bad_curve(good):
    blob = bytearray.fromhex(good["attestation"]["ak_public"])
    rsa = bytes(blob[:2]) + struct.pack(">H", 0x0001) + bytes(blob[4:])
    with pytest.raises(ValueError, match="not ECC"):
        tpm.parse_public(rsa)
    # curveID sits after type, nameAlg, attributes, empty authPolicy, symmetric, scheme+hash
    curve_offset = 2 + 2 + 2 + 4 + 2 + 2 + 4
    assert blob[curve_offset:curve_offset + 2] == b"\x00\x03"
    blob[curve_offset + 1] = 0x04  # NIST P-384
    with pytest.raises(ValueError, match="unsupported curve"):
        tpm.parse_public(bytes(blob)).key()


def test_parse_quote_fixture(good):
    attestation = good["attestation"]
    raw = bytes.fromhex(attestation["quote"])
    assert raw[:4] == b"\xffTCG" and raw[4:6] == b"\x80\x18"
    quote = tpm.parse_quote(raw)
    assert quote.raw == raw
    assert quote.extra_data == good["nonce"]
    assert quote.selection == {tpm.TPM_ALG_SHA256: list(range(10))}
    pcrs = b"".join(bytes.fromhex(attestation["pcrs"][str(i)]) for i in range(10))
    assert quote.pcr_digest == hashlib.sha256(pcrs).digest()
    assert quote.qualified_signer[:2] == b"\x00\x0b" and len(quote.qualified_signer) == 34


def test_parse_quote_rejects_bad_magic_type_and_truncation(good):
    quote = good["attestation"]["quote"]
    with pytest.raises(ValueError, match="magic"):
        tpm.parse_quote(bytes.fromhex(flip(quote, 0)))
    with pytest.raises(ValueError, match="not a quote"):
        tpm.parse_quote(bytes.fromhex(flip(quote, 5)))
    with pytest.raises(ValueError, match="truncated"):
        tpm.parse_quote(bytes.fromhex(quote)[:-1])


def test_pcr_selection_multiple_banks():
    data = struct.pack(">I", 2) + struct.pack(">HB", 0x0004, 3) + bytes([0x01, 0x00, 0x80]) \
        + struct.pack(">HB", 0x000B, 3) + bytes([0xFF, 0x03, 0x00])
    assert tpm.pcr_selection(tpm.Reader(data)) == {0x0004: [0, 23], 0x000B: list(range(10))}


def test_signature_valid_fixture(good):
    attestation = good["attestation"]
    key = tpm.parse_public(bytes.fromhex(attestation["ak_public"]))
    raw = bytes.fromhex(attestation["quote"])
    assert tpm.signature_valid(key, raw, bytes.fromhex(attestation["signature"]))
    assert not tpm.signature_valid(key, raw[:-1] + bytes([raw[-1] ^ 1]), bytes.fromhex(attestation["signature"]))


def test_signature_valid_generated_key():
    private = ec.generate_private_key(ec.SECP256R1())
    key = tpm.parse_public(ak_public_blob(private))
    pcrs = {str(i): bytes([i]) * 32 for i in range(10)}
    raw = quote_blob(b"nonce", {k: v.hex() for k, v in pcrs.items()}, list(range(10)))
    assert tpm.signature_valid(key, raw, signature_blob(private, raw))
    other = ec.generate_private_key(ec.SECP256R1())
    assert not tpm.signature_valid(key, raw, signature_blob(other, raw))


def test_parse_ecdsa_signature_rejects_other_schemes(good):
    signature = good["attestation"]["signature"]
    with pytest.raises(ValueError, match="ECDSA"):
        tpm.parse_ecdsa_signature(bytes.fromhex(flip(signature, 1)))  # algorithm
    with pytest.raises(ValueError, match="ECDSA"):
        tpm.parse_ecdsa_signature(bytes.fromhex(flip(signature, 3)))  # hash


def test_extend_matches_hashlib():
    pcr = bytes(32)
    expected = bytes(32)
    for i in range(5):
        digest = hashlib.sha256(bytes([i])).digest()
        pcr = tpm.extend(pcr, digest)
        expected = hashlib.sha256(expected + digest).digest()
    assert pcr == expected
    assert tpm.extend(bytes(32), bytes(32)) == hashlib.sha256(bytes(64)).digest()
