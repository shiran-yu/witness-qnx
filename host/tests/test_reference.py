"""reference.gpt_event_digest on a synthetic GPT disk, and consistency of the captured reference."""
import hashlib
import struct
import uuid

import pytest

from witness.reference import EXIT_BOOT_SERVICES, UEFI_PCR4_PREFIX, gpt_event_digest
from witness.tpm import extend

SECTOR = 512


def gpt_disk(path, entries: dict[int, bytes], count: int = 128, entry_size: int = 128) -> bytes:
    """Protective MBR, GPT header at LBA 1, entry array at LBA 2; returns the header's first 92 bytes."""
    disk = bytearray(SECTOR * (2 + count * entry_size // SECTOR) + SECTOR * 8)
    header = bytearray(92)
    header[:8] = b"EFI PART"
    struct.pack_into("<IIIIQQQQ", header, 8, 0x00010000, 92, 0xDEADBEEF, 0, 1, len(disk) // SECTOR - 1, 34,
                     len(disk) // SECTOR - 34)
    header[56:72] = uuid.UUID(int=7).bytes_le
    struct.pack_into("<QIII", header, 72, 2, count, entry_size, 0xCAFEF00D)
    disk[SECTOR:SECTOR + 92] = header
    disk[SECTOR + 92:2 * SECTOR] = b"\xaa" * (SECTOR - 92)  # past HeaderSize: not measured
    for index, entry in entries.items():
        offset = 2 * SECTOR + index * entry_size
        disk[offset:offset + len(entry)] = entry
    path.write_bytes(bytes(disk))
    return bytes(header)


def entry(type_guid: int, name: str) -> bytes:
    return (uuid.UUID(int=type_guid).bytes_le + uuid.uuid5(uuid.NAMESPACE_DNS, name).bytes_le
            + struct.pack("<QQQ", 2048, 4095, 0) + name.encode("utf-16-le").ljust(72, b"\0"))


def test_gpt_event_digest(tmp_path):
    used = {0: entry(0xC12A7328F81F11D2BA4B00A0C93EC93B, "EFI"), 2: entry(0x1234, "qnx6")}
    header = gpt_disk(tmp_path / "disk", used)
    expected = hashlib.sha256(header + struct.pack("<Q", 2) + used[0] + used[2]).digest()
    assert gpt_event_digest(str(tmp_path / "disk")) == expected


def test_gpt_empty_type_guid_skipped(tmp_path):
    # an entry with a zero type GUID is unused even if other fields are set
    unused = bytes(16) + entry(1, "x")[16:]
    header = gpt_disk(tmp_path / "disk", {0: entry(1, "a"), 1: unused})
    expected = hashlib.sha256(header + struct.pack("<Q", 1) + entry(1, "a")).digest()
    assert gpt_event_digest(str(tmp_path / "disk")) == expected


def test_gpt_missing(tmp_path):
    (tmp_path / "disk").write_bytes(bytes(4 * SECTOR))
    with pytest.raises(ValueError, match="no GPT"):
        gpt_event_digest(str(tmp_path / "disk"))


def test_captured_reference_pcrs_follow_from_its_digests(reference):
    pcr4 = bytes(32)
    for digest in UEFI_PCR4_PREFIX + [bytes.fromhex(reference["ifs_authenticode"])]:
        pcr4 = extend(pcr4, digest)
    assert pcr4.hex() == reference["pcr"]["4"]
    pcr5 = bytes(32)
    for digest in [UEFI_PCR4_PREFIX[1], bytes.fromhex(reference["gpt_event"])] + EXIT_BOOT_SERVICES:
        pcr5 = extend(pcr5, digest)
    assert pcr5.hex() == reference["pcr"]["5"]
    for pcr in ("8", "9"):
        replay = bytes(32)
        for event in reference["events"][pcr]:
            replay = extend(replay, bytes.fromhex(event["sha256"]))
        assert replay.hex() == reference["pcr"][pcr]
