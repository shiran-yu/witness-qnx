# SPDX-License-Identifier: Apache-2.0
"""PE/COFF Authenticode digest, as UEFI firmware measures an EFI application into PCR 4.

On UEFI targets the QNX IFS *is* the EFI application (EFI/BOOT/BOOTx64.EFI), so this digest
predicts what the firmware extends for the whole boot image: kernel, startup, boot script."""
import hashlib
import struct


def authenticode_digest(image: bytes, algorithm: str = "sha256") -> bytes:
    if image[:2] != b"MZ":
        raise ValueError("not a PE image (no MZ header)")
    pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
    if image[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("not a PE image (no PE signature)")
    coff = pe_offset + 4
    number_of_sections, = struct.unpack_from("<H", image, coff + 2)
    size_of_optional_header, = struct.unpack_from("<H", image, coff + 16)
    optional = coff + 20
    magic, = struct.unpack_from("<H", image, optional)
    if magic == 0x20B:  # PE32+
        data_directories = optional + 112
    elif magic == 0x10B:  # PE32
        data_directories = optional + 96
    else:
        raise ValueError(f"unknown optional header magic 0x{magic:x}")
    checksum_offset = optional + 64
    certificate_entry = data_directories + 4 * 8
    size_of_headers, = struct.unpack_from("<I", image, optional + 60)
    number_of_rva, = struct.unpack_from("<I", image, data_directories - 4)
    certificate_size = struct.unpack_from("<I", image, certificate_entry + 4)[0] if number_of_rva > 4 else 0

    digest = hashlib.new(algorithm)
    if number_of_rva > 4:
        digest.update(image[:checksum_offset])
        digest.update(image[checksum_offset + 4:certificate_entry])
        digest.update(image[certificate_entry + 8:size_of_headers])
    else:
        digest.update(image[:checksum_offset])
        digest.update(image[checksum_offset + 4:size_of_headers])

    section_table = optional + size_of_optional_header
    sections = []
    for index in range(number_of_sections):
        entry = section_table + 40 * index
        size_of_raw_data, pointer_to_raw_data = struct.unpack_from("<II", image, entry + 16)
        if size_of_raw_data:
            sections.append((pointer_to_raw_data, size_of_raw_data))
    hashed = size_of_headers
    for pointer, size in sorted(sections):
        digest.update(image[pointer:pointer + size])
        hashed += size
    if len(image) > hashed:
        digest.update(image[hashed:len(image) - certificate_size])
    return digest.digest()
