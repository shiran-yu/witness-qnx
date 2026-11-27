# SPDX-License-Identifier: Apache-2.0
"""Parse the TPM 2.0 structures witnessd returns, and check the quote signature.

Only what attestation needs: TPM2B_PUBLIC (ECC), TPMS_ATTEST (quote), TPMT_SIGNATURE (ECDSA).
Layouts follow TPM 2.0 Library Part 2 (Structures); all integers are big-endian."""
import hashlib
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_QUOTE = 0x8018
TPM_ALG_ECC = 0x0023
TPM_ALG_ECDSA = 0x0018
TPM_ALG_SHA256 = 0x000B
TPM_ALG_NULL = 0x0010
TPM_ECC_NIST_P256 = 0x0003


class Reader:
    def __init__(self, data: bytes):
        self.data, self.offset = data, 0

    def take(self, n: int) -> bytes:
        if self.offset + n > len(self.data):
            raise ValueError("truncated TPM structure")
        chunk = self.data[self.offset:self.offset + n]
        self.offset += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def tpm2b(self) -> bytes:
        return self.take(self.u16())


def pcr_selection(reader: Reader) -> dict[int, list[int]]:
    """TPML_PCR_SELECTION -> {hash_alg: [pcr indices]}"""
    result = {}
    for _ in range(reader.u32()):
        algorithm = reader.u16()
        select = reader.take(reader.u8())
        result[algorithm] = [8 * byte + bit for byte, bits in enumerate(select) for bit in range(8) if bits >> bit & 1]
    return result


@dataclass
class EccPublicKey:
    curve: int
    x: bytes
    y: bytes
    name: bytes  # TPM object name: nameAlg || H(TPMT_PUBLIC)
    attributes: int = 0  # TPMA_OBJECT
    auth_policy: bytes = b""

    def key(self) -> ec.EllipticCurvePublicKey:
        if self.curve != TPM_ECC_NIST_P256:
            raise ValueError(f"unsupported curve 0x{self.curve:x}")
        return ec.EllipticCurvePublicNumbers(int.from_bytes(self.x, "big"), int.from_bytes(self.y, "big"),
                                             ec.SECP256R1()).public_key()

    def fingerprint(self) -> str:
        return hashlib.sha256(self.x + self.y).hexdigest()[:16]


def parse_public(blob: bytes) -> EccPublicKey:
    """TPM2B_PUBLIC carrying an ECC key (the witnessd attestation key)."""
    outer = Reader(blob)
    area = outer.tpm2b()
    reader = Reader(area)
    key_type, name_alg = reader.u16(), reader.u16()
    if key_type != TPM_ALG_ECC:
        raise ValueError("attestation key is not ECC")
    attributes = reader.u32()
    auth_policy = reader.tpm2b()
    symmetric = reader.u16()
    if symmetric != TPM_ALG_NULL:
        reader.u16(); reader.u16()
    scheme = reader.u16()
    if scheme != TPM_ALG_NULL:
        reader.u16()
    curve = reader.u16()
    kdf = reader.u16()
    if kdf != TPM_ALG_NULL:
        reader.u16()
    x, y = reader.tpm2b(), reader.tpm2b()
    if name_alg != TPM_ALG_SHA256:
        raise ValueError("unexpected nameAlg")
    name = struct.pack(">H", name_alg) + hashlib.sha256(area).digest()
    return EccPublicKey(curve, x, y, name, attributes, auth_policy)


TPMA_OBJECT_FIXEDTPM, TPMA_OBJECT_USERWITHAUTH = 0x2, 0x40
TPMA_OBJECT_RESTRICTED, TPMA_OBJECT_SIGN = 0x10000, 0x40000
TPM_CC_POLICY_PCR = 0x17F


TPM_CC_POLICY_AUTHORIZE = 0x16A
TPM_ECC_NIST_P256 = 0x0003


def ecc_public_area(x: bytes, y: bytes, attributes: int = 0x00040040) -> bytes:
    """TPMT_PUBLIC of an ECDSA-SHA256 P-256 key as TPM2_LoadExternal takes it (default: sign, userWithAuth)."""
    return (struct.pack(">HHIH", TPM_ALG_ECC, TPM_ALG_SHA256, attributes, 0)
            + struct.pack(">HHHHH", TPM_ALG_NULL, TPM_ALG_ECDSA, TPM_ALG_SHA256, TPM_ECC_NIST_P256, TPM_ALG_NULL)
            + struct.pack(">H", len(x)) + x + struct.pack(">H", len(y)) + y)


def object_name(public_area: bytes) -> bytes:
    return struct.pack(">H", TPM_ALG_SHA256) + hashlib.sha256(public_area).digest()


def policy_authorize_digest(key_name: bytes, policy_ref: bytes = b"") -> bytes:
    """authPolicy satisfied by any policy that the key named `key_name` signed (TPM2_PolicyAuthorize)."""
    digest = hashlib.sha256(bytes(32) + struct.pack(">I", TPM_CC_POLICY_AUTHORIZE) + key_name).digest()
    return hashlib.sha256(digest + policy_ref).digest()


def pcr_policy_digest(values: dict[int, bytes], previous: bytes = bytes(32)) -> bytes:
    """Policy digest after TPM2_PolicyPCR over these SHA-256 PCR values (from `previous`, default a fresh session)."""
    mask = sum(1 << i for i in values)
    selection = struct.pack(">IHB", 1, TPM_ALG_SHA256, 3) + mask.to_bytes(3, "little")
    pcr_digest = hashlib.sha256(b"".join(values[i] for i in sorted(values))).digest()
    return hashlib.sha256(previous + struct.pack(">I", TPM_CC_POLICY_PCR) + selection + pcr_digest).digest()


TPM_CC_POLICY_NV = 0x149
TPM_EO_BITCLEAR = 0x000B


def nv_name(index: int, attributes: int, size: int) -> bytes:
    """Name of an NV index: nameAlg || H(TPMS_NV_PUBLIC), empty authPolicy."""
    public = struct.pack(">IHIHH", index, TPM_ALG_SHA256, attributes, 0, size)
    return struct.pack(">H", TPM_ALG_SHA256) + hashlib.sha256(public).digest()


def policy_nv_digest(previous: bytes, name: bytes, operand: bytes, offset: int, operation: int) -> bytes:
    """Policy digest after TPM2_PolicyNV."""
    args = hashlib.sha256(operand + struct.pack(">HH", offset, operation)).digest()
    return hashlib.sha256(previous + struct.pack(">I", TPM_CC_POLICY_NV) + args + name).digest()


@dataclass
class Quote:
    raw: bytes
    qualified_signer: bytes
    extra_data: bytes  # the verifier's nonce
    clock: int
    reset_count: int
    restart_count: int
    safe: bool
    firmware_version: int
    selection: dict
    pcr_digest: bytes


def parse_quote(raw: bytes) -> Quote:
    reader = Reader(raw)
    if reader.u32() != TPM_GENERATED_VALUE:
        raise ValueError("quote not generated by a TPM (magic mismatch)")
    if reader.u16() != TPM_ST_ATTEST_QUOTE:
        raise ValueError("attestation is not a quote")
    signer, extra = reader.tpm2b(), reader.tpm2b()
    clock, resets, restarts, safe = reader.u64(), reader.u32(), reader.u32(), reader.u8()
    firmware = reader.u64()
    selection = pcr_selection(reader)
    digest = reader.tpm2b()
    return Quote(raw, signer, extra, clock, resets, restarts, bool(safe), firmware, selection, digest)


TPM_ST_ATTEST_CERTIFY = 0x8017


def parse_certify(raw: bytes) -> tuple[bytes, bytes]:
    """TPMS_ATTEST from TPM2_Certify -> (extraData, name of the certified object)."""
    reader = Reader(raw)
    if reader.u32() != TPM_GENERATED_VALUE:
        raise ValueError("certification not generated by a TPM (magic mismatch)")
    if reader.u16() != TPM_ST_ATTEST_CERTIFY:
        raise ValueError("attestation is not a certification")
    reader.tpm2b()  # qualifiedSigner
    extra = reader.tpm2b()
    reader.u64(), reader.u32(), reader.u32(), reader.u8(), reader.u64()  # clockInfo, firmwareVersion
    return extra, reader.tpm2b()


def parse_ecdsa_signature(blob: bytes) -> bytes:
    """TPMT_SIGNATURE (ECDSA/SHA-256) -> DER signature for cryptography."""
    reader = Reader(blob)
    if reader.u16() != TPM_ALG_ECDSA or reader.u16() != TPM_ALG_SHA256:
        raise ValueError("signature is not ECDSA-SHA256")
    r, s = reader.tpm2b(), reader.tpm2b()
    return encode_dss_signature(int.from_bytes(r, "big"), int.from_bytes(s, "big"))


def signature_valid(key: EccPublicKey, quote_raw: bytes, signature_blob: bytes) -> bool:
    try:
        key.key().verify(parse_ecdsa_signature(signature_blob), quote_raw, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def extend(pcr: bytes, digest: bytes) -> bytes:
    return hashlib.sha256(pcr + digest).digest()
