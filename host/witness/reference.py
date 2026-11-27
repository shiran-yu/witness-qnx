# SPDX-License-Identifier: Apache-2.0
"""Reference values for one QNX image, computed on the build host from the build output only."""
import datetime
import hashlib
import os
import re

from .buildfile import file_digests
from .pe import authenticode_digest
from .tpm import extend

# Events OVMF extends into PCR 4 before handing over to the boot application (EDK2 Tcg2Dxe):
# EV_EFI_ACTION "Calling EFI Application from Boot Option", EV_SEPARATOR, then the application itself.
UEFI_PCR4_PREFIX = [hashlib.sha256(b"Calling EFI Application from Boot Option").digest(),
                    hashlib.sha256(b"\0\0\0\0").digest()]
MISSING_DIGEST = hashlib.sha256(b"witness:missing").hexdigest()  # what witness-measure logs for an absent file
SYSTEM_MARKER = "witness:system-measured"


def _manifest_path(ifs_build: str) -> str:
    for line in open(ifs_build, encoding="utf-8", errors="replace"):
        match = re.search(r"witness\.manifest=(\S+)", line)
        if match:
            return match.group(1)
    raise ValueError(f"{ifs_build} has no witness.manifest: run src/image/witness-image.sh on this image")


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

    files = file_digests(os.path.join(build, "system.build"), image_dir, "/system")
    manifest = read_manifest(_manifest_path(os.path.join(build, "ifs.build")))

    pcr8_events = []
    pcr8 = bytes(32)
    for path in manifest:
        digest = files.get(path, MISSING_DIGEST)
        pcr8_events.append({"type": "file" if path in files else "missing", "path": path, "sha256": digest})
        pcr8 = extend(pcr8, bytes.fromhex(digest))
    marker = hashlib.sha256(SYSTEM_MARKER.encode()).hexdigest()
    pcr8_events.append({"type": "marker", "path": SYSTEM_MARKER, "sha256": marker})
    pcr8 = extend(pcr8, bytes.fromhex(marker))

    reference = {
        "version": 1,
        "created": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "image": os.path.abspath(image_dir),
        "boot_mode": "uefi" if uefi else "kernel",
        "ifs_sha256": hashlib.sha256(open(ifs_path, "rb").read()).hexdigest(),
        "pcr8_events": pcr8_events,
        "pcr": {"8": pcr8.hex()},
        "files": files,
    }
    if uefi:
        authenticode = authenticode_digest(open(ifs_path, "rb").read())
        pcr4 = bytes(32)
        for digest in UEFI_PCR4_PREFIX + [authenticode]:
            pcr4 = extend(pcr4, digest)
        reference["ifs_authenticode"] = authenticode.hex()
        reference["pcr"]["4"] = pcr4.hex()
    return reference
