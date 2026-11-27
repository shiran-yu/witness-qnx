# SPDX-License-Identifier: Apache-2.0
"""Reference values for one QNX image, computed on the build host from the build output only."""
import datetime
import hashlib
import os
import re
import struct

from .buildfile import file_digests
from .pe import authenticode_digest
from .tpm import extend

# Events OVMF extends into PCR 4 before handing over to the boot application (EDK2 Tcg2Dxe):
# EV_EFI_ACTION "Calling EFI Application from Boot Option", EV_SEPARATOR, then the application itself.
UEFI_PCR4_PREFIX = [hashlib.sha256(b"Calling EFI Application from Boot Option").digest(),
                    hashlib.sha256(b"\0\0\0\0").digest()]
# PCR 5 on OVMF: EV_SEPARATOR, EV_EFI_GPT_EVENT (boot disk partition table), then the two ExitBootServices actions
EXIT_BOOT_SERVICES = [hashlib.sha256(b"Exit Boot Services Invocation").digest(),
                      hashlib.sha256(b"Exit Boot Services Returned with Success").digest()]
MISSING_DIGEST =hashlib.sha256(b"witness:missing").hexdigest()  # what witness-measure logs for an absent file
SYSTEM_MARKER = "witness:system-measured"


def _manifest_path(ifs_build: str, name: str) -> str | None:
    for line in open(ifs_build, encoding="utf-8", errors="replace"):
        match = re.search(re.escape(name) + r"=(\S+)", line)
        if match:
            return match.group(1)
    return None


def _expected_events(manifest: list[str], files: dict[str, str], marker: str | None) -> tuple[list[dict], str]:
    """The events witness-measure will log for a manifest, and the PCR value they produce."""
    events, pcr = [], bytes(32)
    for path in manifest:
        digest = files.get(path, MISSING_DIGEST)
        events.append({"type": "file" if path in files else "missing", "path": path, "sha256": digest})
        pcr = extend(pcr, bytes.fromhex(digest))
    if marker:
        digest = hashlib.sha256(marker.encode()).hexdigest()
        events.append({"type": "marker", "path": marker, "sha256": digest})
        pcr = extend(pcr, bytes.fromhex(digest))
    return events, pcr.hex()


def gpt_event_digest(disk_path: str, sector: int = 512) -> bytes:
    """SHA-256 of UEFI_GPT_DATA as EDK2 measures it: GPT header, partition count, non-empty entries."""
    with open(disk_path, "rb") as disk:
        disk.seek(sector)
        header_sector = disk.read(sector)
        if header_sector[:8] != b"EFI PART":
            raise ValueError(f"{disk_path} has no GPT")
        header = header_sector[:struct.unpack_from("<I", header_sector, 12)[0]]
        entries_lba, count, entry_size = struct.unpack_from("<QII", header_sector, 72)
        disk.seek(entries_lba * sector)
        table = disk.read(count * entry_size)
    used = [table[i:i + entry_size] for i in range(0, len(table), entry_size) if table[i:i + 16] != bytes(16)]
    return hashlib.sha256(header + struct.pack("<Q", len(used)) + b"".join(used)).digest()


def read_manifest(path: str) -> list[str]:
    entries = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#"):
            entries.append(line)
    return entries


def build_reference(image_dir: str) -> dict:
    build = os.path.join(image_dir, "output", "build")
    ifs_path = os.path.join(image_dir, "output", "ifs.bin")
    uefi = "BOOTx64.EFI" in open(os.path.join(build, "boot_part.build"), errors="replace").read() \
        if os.path.exists(os.path.join(build, "boot_part.build")) else False

    ifs_build = os.path.join(build, "ifs.build")
    files = file_digests(os.path.join(build, "system.build"), image_dir, "/system")
    system_manifest = _manifest_path(ifs_build, "witness.manifest")
    if system_manifest is None:
        raise ValueError(f"{ifs_build} has no witness.manifest: run src/image/witness-image.sh on this image")
    apps_manifest = _manifest_path(ifs_build, "witness-apps.manifest")

    events, pcr = {}, {}
    events["8"], pcr["8"] = _expected_events(read_manifest(system_manifest), files, SYSTEM_MARKER)
    events["9"], pcr["9"] = _expected_events(read_manifest(apps_manifest) if apps_manifest else [], files, None)

    reference = {
        "version": 2,
        "created": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "image": os.path.basename(os.path.normpath(image_dir)),
        "boot_mode": "uefi" if uefi else "kernel",
        "ifs_sha256": hashlib.sha256(open(ifs_path, "rb").read()).hexdigest(),
        "events": events,
        "pcr": pcr,
        "files": files,
    }
    if uefi:
        authenticode = authenticode_digest(open(ifs_path, "rb").read())
        pcr4 = bytes(32)
        for digest in UEFI_PCR4_PREFIX + [authenticode]:
            pcr4 = extend(pcr4, digest)
        reference["ifs_authenticode"] = authenticode.hex()
        reference["pcr"]["4"] = pcr4.hex()
        pcr5 = bytes(32)
        gpt = gpt_event_digest(os.path.join(image_dir, "output", "disk-qemu"))
        for digest in [UEFI_PCR4_PREFIX[1], gpt] + EXIT_BOOT_SERVICES:
            pcr5 = extend(pcr5, digest)
        reference["gpt_event"] = gpt.hex()
        reference["pcr"]["5"] = pcr5.hex()
    return reference
