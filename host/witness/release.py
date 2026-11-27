# SPDX-License-Identifier: Apache-2.0
"""Signed releases: the device key's TPM policy is PolicyAuthorize(release key), so any release
whose PCR policy the release key signed can use the key, without re-provisioning the device."""
import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .tpm import ecc_public_area, object_name, pcr_policy_digest, policy_authorize_digest

RELEASE_PCRS = (4, 5, 8, 9)  # predicted from the build: signed per release
FIRMWARE_KEY_PCRS = (0, 2, 7)  # bound per device after PolicyAuthorize (witnessd FIRMWARE_PCR_MASK)


def make_release_key(path: str) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as out:
        out.write(pem)


def load_release_key(path: str) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(open(path, "rb").read(), None)


def public_xy(key: ec.EllipticCurvePrivateKey) -> tuple[bytes, bytes]:
    numbers = key.public_key().public_numbers()
    return numbers.x.to_bytes(32, "big"), numbers.y.to_bytes(32, "big")


def release_key_name(x: bytes, y: bytes) -> bytes:
    return object_name(ecc_public_area(x, y))


def sign_release(reference: dict, key: ec.EllipticCurvePrivateKey) -> dict:
    """The signed PCR policy of one release: what witnessd needs for TPM2_PolicyAuthorize."""
    values = {i: bytes.fromhex(reference["pcr"][str(i)]) for i in RELEASE_PCRS}
    approved = pcr_policy_digest(values)
    a_hash = hashlib.sha256(approved).digest()  # aHash = H(approvedPolicy || policyRef), policyRef empty
    r, s = utils.decode_dss_signature(key.sign(a_hash, ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
    x, y = public_xy(key)
    return {"pcr_mask": sum(1 << i for i in RELEASE_PCRS), "approved_policy": approved.hex(),
            "signature_r": r.to_bytes(32, "big").hex(), "signature_s": s.to_bytes(32, "big").hex(),
            "release_x": x.hex(), "release_y": y.hex(), "image": reference.get("image"),
            "ifs_sha256": reference.get("ifs_sha256")}


def policy_file_text(policy: dict) -> str:
    """The line format witnessd reads: one `key value` per line, values in hex."""
    keys = ("pcr_mask", "approved_policy", "signature_r", "signature_s", "release_x", "release_y")
    return "".join(f"{k} {policy[k]:x}\n" if k == "pcr_mask" else f"{k} {policy[k]}\n" for k in keys)


def device_key_policy(x: bytes, y: bytes) -> bytes:
    """The authPolicy witnessd gives the device key when it knows the release public key."""
    return policy_authorize_digest(release_key_name(x, y))
