# SPDX-License-Identifier: Apache-2.0
"""Compute the digest every file will have on the target, from a mkqnximage buildfile.

mkqnx6fsimg copies host files byte for byte, so a file's on-target SHA-256 is the SHA-256 of its host
source; inline files ({ ... }) are their lines joined with newlines plus a final newline. This gives
reference values from the build output alone, with no "golden device" to trust."""
import hashlib
import os
import re

ATTRIBUTE = re.compile(r"^\s*(\[[^\]]*\]\s*)+")


def _search_paths(line: str, base: str) -> list[str]:
    paths = line.strip()[len("[search="):-1].split(":")
    return [p if os.path.isabs(p) else os.path.join(base, p) for p in paths]


def _resolve(source: str, search: list[str], base: str) -> str | None:
    if os.path.isabs(source):
        return source if os.path.isfile(source) else None
    for directory in search + [base]:
        candidate = os.path.join(directory, source)
        if os.path.isfile(candidate):
            return candidate
    return None


LINK_PREFIX = b"witness:link:"  # witness-measure measures a symlink as SHA256(LINK_PREFIX + target)


def file_digests(buildfile: str, image_dir: str, mount_point: str = "/system",
                 links: set[str] | None = None) -> dict[str, str]:
    """Map each on-target path ('/system/bin/sshd') to its expected SHA-256 hex digest.
    Hard links get their target's digest; symlinks their target string's, and are added to `links`."""
    lines = open(buildfile, encoding="utf-8", errors="replace").read().split("\n")
    search: list[str] = []
    digests: dict[str, str] = {}
    hard_links: list[tuple[str, str]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        stripped = line.strip()
        if stripped.startswith("[search="):
            search = _search_paths(stripped, image_dir)
            continue
        if not stripped or stripped.startswith("#"):
            continue
        body = ATTRIBUTE.sub("", line).strip()
        if not body or body.startswith("["):
            continue
        if "type=dir" in line:
            continue
        target, _, source = body.partition("=")
        target, source = target.strip(), source.strip()
        on_target = os.path.normpath(os.path.join(mount_point, target.lstrip("/")))
        if "type=hlink" in line:
            hard_links.append((on_target, os.path.normpath(os.path.join(os.path.dirname(on_target), source))))
            continue
        if "type=link" in line:
            digests[on_target] = hashlib.sha256(LINK_PREFIX + source.encode()).hexdigest()
            if links is not None:
                links.add(on_target)
            continue
        if source == "{":
            content = []
            while i < len(lines) and lines[i].strip() != "}":
                content.append(lines[i])
                i += 1
            i += 1
            # inside inline files a backslash always escapes: the next character is copied as is (mkifs docs)
            data = re.sub(r"\\(.)", r"\1", "\n".join(content) + "\n", flags=re.DOTALL).encode()
        else:
            resolved = _resolve(source or target, search, image_dir)
            if resolved is None:
                continue  # optional file not present in this SDP; the target will measure it as missing
            data = open(resolved, "rb").read()
        digests[on_target] = hashlib.sha256(data).hexdigest()
    for on_target, existing in hard_links:
        if existing in digests:
            digests[on_target] = digests[existing]
    return digests
