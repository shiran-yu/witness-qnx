# SPDX-License-Identifier: Apache-2.0
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from witness.release import RELEASE_PCRS, device_key_policy, policy_file_text, public_xy, sign_release
from witness.tpm import pcr_policy_digest


def test_signed_release_verifies_under_the_release_key(reference):
    key = ec.generate_private_key(ec.SECP256R1())
    policy = sign_release(reference, key)
    assert bytes.fromhex(policy["approved_policy"]) == pcr_policy_digest(
        {i: bytes.fromhex(reference["pcr"][str(i)]) for i in RELEASE_PCRS})
    signature = utils.encode_dss_signature(int(policy["signature_r"], 16), int(policy["signature_s"], 16))
    a_hash = hashlib.sha256(bytes.fromhex(policy["approved_policy"])).digest()
    key.public_key().verify(signature, a_hash, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    assert policy_file_text(policy).startswith("pcr_mask 330\n")  # PCR 4,5,8,9 = 0x330


def test_device_key_policy_depends_only_on_the_release_key():
    a, b = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    assert device_key_policy(*public_xy(a)) == device_key_policy(*public_xy(a))
    assert device_key_policy(*public_xy(a)) != device_key_policy(*public_xy(b))


def test_update_release_changes_only_the_replaced_file(tmp_path):
    from witness.reference import build_reference
    import os
    image = os.path.join(os.path.dirname(__file__), "..", "..", ".work", "vm")
    if not os.path.exists(os.path.join(image, "output", "build", "system.build")):
        import pytest
        pytest.skip("needs a built image in src/.work/vm")
    v1 = build_reference(image)
    new = tmp_path / "sshd_config"
    new.write_text("MaxAuthTries 3\n")
    v2 = build_reference(image, {"/system/etc/ssh/sshd_config": str(new)})
    changed = [p for p in v1["files"] if v1["files"][p] != v2["files"][p]]
    assert changed == ["/system/etc/ssh/sshd_config"]
    assert v1["pcr"]["8"] != v2["pcr"]["8"] and v1["pcr"]["4"] == v2["pcr"]["4"]
