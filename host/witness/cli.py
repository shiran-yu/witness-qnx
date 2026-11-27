# SPDX-License-Identifier: Apache-2.0
"""witness: build-host and fleet-side tool.

  witness reference <image-dir> [-o reference.json]      reference values from the build output
  witness enroll  --device HOST:PORT -r reference.json   record AK + firmware baseline (known-good boot)
  witness verify  --device HOST:PORT -r reference.json   challenge, appraise, print the verdict
"""
import argparse
import json
import os
import socket
import sys

from .reference import build_reference
from .verify import appraise, enrollment_from

GREEN, RED, DIM, BOLD, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"


def request_attestation(device: str, nonce: bytes, timeout: float = 20.0) -> dict:
    host, _, port = device.rpartition(":")
    with socket.create_connection((host or "127.0.0.1", int(port)), timeout=timeout) as connection:
        connection.sendall(b"ATTEST " + nonce.hex().encode() + b"\n")
        data = b""
        while chunk := connection.recv(65536):
            data += chunk
    if not data:
        raise ConnectionError(f"no answer from witnessd at {device}")
    return json.loads(data)


def enrollment_path(directory: str, device: str) -> str:
    return os.path.join(directory, "enrolled-" + device.replace(":", "_") + ".json")


def print_verdict(verdict, device: str) -> None:
    color = GREEN if verdict.trusted else RED
    print(f"{BOLD}{device}{RESET}  {color}{BOLD}{'TRUSTED' if verdict.trusted else 'NOT TRUSTED'}{RESET}"
          f"   device secret: {verdict.sealed}")
    for check in verdict.checks:
        mark = f"{GREEN}pass{RESET}" if check.ok else f"{RED}FAIL{RESET}"
        print(f"  {mark}  {check.name:<28} {DIM}{check.detail}{RESET}")
    for finding in verdict.findings:
        line = f"  {RED}{finding['kind'].upper():>12}{RESET}  PCR {finding['pcr']}  {finding['what']}"
        if "expected" in finding:
            line += f"\n{'':18}expected {finding['expected'][:16]}…  got {str(finding['actual'])[:16]}…"
        print(line)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="witness", description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    reference = commands.add_parser("reference", help="compute reference values from a mkqnximage directory")
    reference.add_argument("image_dir")
    reference.add_argument("-o", "--output", default="reference.json")

    for name in ("enroll", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--device", required=True, help="HOST:PORT of witnessd")
        command.add_argument("-r", "--reference", required=True)
        command.add_argument("--state", default=".witness", help="directory for enrollment records")
        command.add_argument("--json", action="store_true", help="print the verdict as JSON")

    args = parser.parse_args(argv)
    if args.command == "reference":
        result = build_reference(args.image_dir)
        with open(args.output, "w") as out:
            json.dump(result, out, indent=1)
        print(f"wrote {args.output}: boot={result['boot_mode']} "
              + " ".join(f"PCR{k}={v[:12]}…" for k, v in sorted(result["pcr"].items()))
              + f", {len(result['events']['8'])} PCR 8 + {len(result['events']['9'])} PCR 9 expected events,"
              + f" {len(result['files'])} files")
        return 0

    reference_values = json.load(open(args.reference))
    os.makedirs(args.state, exist_ok=True)
    path = enrollment_path(args.state, args.device)
    nonce = os.urandom(20)
    attestation = request_attestation(args.device, nonce)

    if args.command == "enroll":
        verdict = appraise(attestation, nonce, reference_values, None)
        if not verdict.trusted:
            print_verdict(verdict, args.device)
            print(f"{RED}refusing to enroll a device that does not match the release{RESET}")
            return 1
        with open(path, "w") as out:
            json.dump(enrollment_from(attestation), out, indent=1)
        print(f"enrolled {args.device}: {path}")

    enrollment = json.load(open(path)) if os.path.exists(path) else None
    verdict = appraise(attestation, nonce, reference_values, enrollment)
    if args.json:
        print(json.dumps(verdict.to_dict(), indent=1))
    else:
        print_verdict(verdict, args.device)
    return 0 if verdict.trusted else 2


if __name__ == "__main__":
    sys.exit(main())
