"""pe.authenticode_digest on a synthetic PE32+, checked against a layout-aware reference hash."""
import hashlib
import struct

import pytest

from witness.pe import authenticode_digest

PE_OFFSET = 0x40
OPTIONAL = PE_OFFSET + 4 + 20  # optional header start
CHECKSUM = OPTIONAL + 64
CERT_ENTRY = OPTIONAL + 112 + 4 * 8  # data directory 4: certificate table
SECTION_TABLE = OPTIONAL + 240
HEADERS = 0x200
SECTION = (0x200, 0x400)  # file offset, raw size


def build_pe(cert: bytes = b"", trailer: bytes = b"", rva_count: int = 16, checksum: int = 0x1234) -> bytes:
    image = bytearray(HEADERS)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, PE_OFFSET)
    image[PE_OFFSET:PE_OFFSET + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, PE_OFFSET + 4, 0x8664, 1, 0, 0, 0, 240, 0x22)
    struct.pack_into("<H", image, OPTIONAL, 0x20B)
    struct.pack_into("<I", image, OPTIONAL + 16, 0x1000)  # entry point, part of hashed headers
    struct.pack_into("<I", image, OPTIONAL + 60, HEADERS)
    struct.pack_into("<I", image, CHECKSUM, checksum)
    struct.pack_into("<I", image, OPTIONAL + 108, rva_count)
    struct.pack_into("<8sIIII", image, SECTION_TABLE, b".text", SECTION[1], 0x1000, SECTION[1], SECTION[0])
    image += bytes((i * 7 + 3) & 0xFF for i in range(SECTION[1]))
    image += trailer
    if cert:
        struct.pack_into("<II", image, CERT_ENTRY, len(image), len(cert))
        image += cert
    return bytes(image)


def reference_digest(image: bytes, cert_size: int, rva_count: int = 16) -> bytes:
    """Authenticode steps written out for the fixed layout above."""
    digest = hashlib.sha256()
    if rva_count > 4:
        digest.update(image[:CHECKSUM] + image[CHECKSUM + 4:CERT_ENTRY] + image[CERT_ENTRY + 8:HEADERS])
    else:
        digest.update(image[:CHECKSUM] + image[CHECKSUM + 4:HEADERS])
    end_of_section = SECTION[0] + SECTION[1]
    digest.update(image[SECTION[0]:end_of_section])
    digest.update(image[end_of_section:len(image) - cert_size])
    return digest.digest()


def test_without_certificate():
    image = build_pe()
    assert authenticode_digest(image) == reference_digest(image, 0)


def test_with_certificate_and_trailing_data():
    cert = b"\x08\x00\x00\x00\x00\x02\x02\x00" + b"signature" * 10
    image = build_pe(cert=cert, trailer=b"debug data")
    assert authenticode_digest(image) == reference_digest(image, len(cert))
    # the trailer is hashed, the certificate and its directory entry are not
    assert authenticode_digest(image) != authenticode_digest(build_pe(cert=cert, trailer=b"debug datb"))
    assert authenticode_digest(image) == authenticode_digest(build_pe(trailer=b"debug data"))


def test_excluded_fields_do_not_change_digest():
    assert authenticode_digest(build_pe(checksum=1)) == authenticode_digest(build_pe(checksum=2))
    cert = b"\x08\x00\x00\x00\x00\x02\x02\x00" + b"A" * 32
    assert authenticode_digest(build_pe(cert=cert)) == authenticode_digest(build_pe(cert=cert.replace(b"A", b"B")))


def test_hashed_bytes_change_digest():
    image = bytearray(build_pe())
    baseline = authenticode_digest(bytes(image))
    for offset in (OPTIONAL + 16, SECTION_TABLE, SECTION[0] + 5):
        changed = bytearray(image)
        changed[offset] ^= 1
        assert authenticode_digest(bytes(changed)) != baseline, offset


def test_few_data_directories():
    # with no certificate directory only the checksum is skipped in the headers
    image = build_pe(rva_count=4)
    assert authenticode_digest(image) == reference_digest(image, 0, rva_count=4)


def test_sha1_algorithm():
    image = build_pe()
    assert len(authenticode_digest(image, "sha1")) == 20


def test_rejects_non_pe():
    with pytest.raises(ValueError, match="MZ"):
        authenticode_digest(b"\x7fELF" + bytes(100))
    image = bytearray(build_pe())
    image[PE_OFFSET:PE_OFFSET + 4] = b"NE\0\0"
    with pytest.raises(ValueError, match="PE signature"):
        authenticode_digest(bytes(image))
    image = bytearray(build_pe())
    struct.pack_into("<H", image, OPTIONAL, 0x107)
    with pytest.raises(ValueError, match="magic"):
        authenticode_digest(bytes(image))
