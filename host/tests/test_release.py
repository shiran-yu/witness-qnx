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


# real QEMU captures under release v2 (signed): the current release, and a rollback to the signed v1
RELEASE_KEY_CHECK = "device key (signed release + PCR 0,2,7)"


def _capture(name):
    from conftest import load
    data = load(name)
    return data["attestation"], bytes.fromhex(data["nonce"])


def _appraise(capture, reference=None, enrollment=None):
    from conftest import load
    from witness.verify import appraise
    attestation, nonce = _capture(capture)
    return appraise(attestation, nonce, reference or load("release/reference.json"),
                    enrollment or load("release/enrollment.json"))


def test_current_signed_release_is_trusted():
    verdict = _appraise("release/attestation-v2-current.json")
    assert verdict.trusted and verdict.sealed == "unsealed"
    assert {c.name: c.ok for c in verdict.checks}[RELEASE_KEY_CHECK]


def test_rollback_to_an_older_signed_release_is_refused_by_the_tpm():
    verdict = _appraise("release/attestation-v1-rolled-back.json")
    key = next(c for c in verdict.checks if c.name == RELEASE_KEY_CHECK)
    assert not verdict.trusted and not key.ok and verdict.sealed == "locked"
    # TPM_RC_POLICY from PolicyNV (a tampered boot fails PolicyPCR with TPM_RC_VALUE instead)
    assert "TPM refused" in key.detail and "policy failure" in key.detail


def test_release_number_is_part_of_the_signed_policy(reference):
    from witness.release import approved_policy, policy_file_text, sign_release
    values = {i: bytes.fromhex(reference["pcr"][str(i)]) for i in RELEASE_PCRS}
    assert len({approved_policy(values, None), approved_policy(values, 1), approved_policy(values, 2)}) == 3
    key = ec.generate_private_key(ec.SECP256R1())
    assert policy_file_text(sign_release(reference, key, 2)).endswith("release_number 2\n")
    import pytest
    with pytest.raises(ValueError):
        sign_release(reference, key, 64)


def test_device_key_policy_chains_the_enrolled_firmware():
    from conftest import load
    enrollment = load("release/enrollment.json")
    enrollment["firmware_pcrs"]["0"] = "00" * 32
    key = next(c for c in _appraise("release/attestation-v2-current.json", enrollment=enrollment).checks
               if c.name == RELEASE_KEY_CHECK)
    assert not key.ok and key.detail == "key is not bound to the released state"


def test_device_key_under_another_release_key_fails():
    from conftest import load
    reference = load("release/reference.json")
    other = ec.generate_private_key(ec.SECP256R1())
    x, y = public_xy(other)
    reference["release"]["release_x"], reference["release"]["release_y"] = x.hex(), y.hex()
    key = next(c for c in _appraise("release/attestation-v2-current.json", reference=reference).checks
               if c.name == RELEASE_KEY_CHECK)
    assert not key.ok and key.detail == "key is not bound to the released state"


def _other_release(reference):
    """The same signed release key and number, but PCR 8 of another release (as if v2 were not current)."""
    from witness.release import approved_policy
    reference["pcr"]["8"] = "11" * 32
    values = {i: bytes.fromhex(reference["pcr"][str(i)]) for i in RELEASE_PCRS}
    reference["release"]["approved_policy"] = approved_policy(values, reference["release"]["release_number"]).hex()
    return reference


def test_older_release_without_tpm_refusal_is_named():
    from conftest import load
    verdict = _appraise("release/attestation-v2-current.json", reference=_other_release(load("release/reference.json")))
    key = next(c for c in verdict.checks if c.name == RELEASE_KEY_CHECK)
    assert key.detail == "device booted another signed release, not the current one"
    assert verdict.sealed == "released to an old release" and verdict.sealed_proven


def test_rollback_message_needs_a_proven_key():
    from conftest import load
    from witness.verify import appraise
    data = load("release/attestation-v2-current.json")
    data["attestation"]["device_key"].pop("certify")
    verdict = appraise(data["attestation"], bytes.fromhex(data["nonce"]), _other_release(load("release/reference.json")),
                       load("release/enrollment.json"))
    key = next(c for c in verdict.checks if c.name == RELEASE_KEY_CHECK)
    assert key.detail == "key is not certified by this device's attestation key" and verdict.sealed == "locked"


def test_policy_nv_digest_matches_what_the_tpm_accepted():
    """release/reference.json's approved policy was accepted by the live (sw)TPM for its release number."""
    from conftest import load
    from witness.release import approved_policy
    reference = load("release/reference.json")
    values = {i: bytes.fromhex(reference["pcr"][str(i)]) for i in RELEASE_PCRS}
    assert approved_policy(values, reference["release"]["release_number"]).hex() == \
        reference["release"]["approved_policy"]
