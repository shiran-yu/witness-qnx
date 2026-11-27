# SPDX-License-Identifier: Apache-2.0
"""witness: build-host and fleet-side tool.

  witness reference <image-dir> [-o reference.json]      reference values from the build output
  witness enroll  --device HOST:PORT -r reference.json   record AK + firmware baseline (known-good boot)
  witness verify  --device HOST:PORT -r reference.json   challenge, appraise, print the verdict
  witness dashboard -r reference.json --device NAME=HOST:PORT [--device ...]   fleet web dashboard
  witness dashboard --replay tests/fixtures              the dashboard on captured evidence (no QNX, no TPM)
"""
import argparse
import json
import os
import socket
import sys
import time

from .reference import build_reference
from .verify import appraise, enrollment_from

GREEN, RED, DIM, BOLD, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"
MAX_REPLY = 4 << 20  # bytes; a real attestation is about 40 KB


def safe(text) -> str:
    """Device-supplied text without control characters (no terminal escapes from the agent)."""
    return "".join(c if c.isprintable() else "?" for c in str(text))


def request_attestation(device: str, nonce: bytes, timeout: float = 20.0) -> dict:
    host, _, port = device.rpartition(":")
    deadline = time.monotonic() + timeout  # total budget, not per read: a trickling device times out too
    with socket.create_connection((host or "127.0.0.1", int(port)), timeout=timeout) as connection:
        connection.sendall(b"ATTEST " + nonce.hex().encode() + b"\n")
        data = b""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"no complete answer from {device} within {timeout:g} s")
            connection.settimeout(remaining)
            chunk = connection.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) > MAX_REPLY:
                raise ValueError(f"reply from {device} exceeds {MAX_REPLY} bytes")
    if not data:
        raise ConnectionError(f"no answer from witnessd at {device}")
    return json.loads(data)


def enrollment_path(directory: str, device: str) -> str:
    return os.path.join(directory, "enrolled-" + device.replace(":", "_") + ".json")


def print_verdict(verdict, device: str) -> None:
    color = GREEN if verdict.trusted else RED
    print(f"{BOLD}{device}{RESET}  {color}{BOLD}{'TRUSTED' if verdict.trusted else 'NOT TRUSTED'}{RESET}"
          f"   device key: {'released' if verdict.sealed == 'unsealed' else safe(verdict.sealed)} "
          f"{DIM}({'proven by TPM signature' if verdict.sealed_proven else 'agent’s claim, not verified'}){RESET}")
    for check in verdict.checks:
        mark = f"{GREEN}pass{RESET}" if check.ok else f"{RED}FAIL{RESET}"
        print(f"  {mark}  {check.name:<28} {DIM}{safe(check.detail)}{RESET}")
    for finding in verdict.findings:
        line = f"  {RED}{finding['kind'].upper():>12}{RESET}  PCR {finding['pcr']}  {safe(finding['what'])}"
        if "expected" in finding:
            line += f"\n{'':18}expected {finding['expected'][:16]}…  got {safe(finding['actual'])[:16]}…"
        print(line)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="witness", description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    reference = commands.add_parser("reference", help="compute reference values from a mkqnximage directory")
    reference.add_argument("image_dir")
    reference.add_argument("-o", "--output", default="reference.json")
    reference.add_argument("--replace", action="append", default=[], metavar="TARGET_PATH=HOST_FILE",
                           help="update release: the build with this file replaced (repeatable)")
    reference.add_argument("--release-key", metavar="PEM",
                           help="sign this release's PCR policy (writes <output>.policy for the device)")

    release_key = commands.add_parser("release-key", help="create the release signing key (keep it off devices)")
    release_key.add_argument("path")

    for name in ("enroll", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--device", required=True, help="HOST:PORT of witnessd")
        command.add_argument("-r", "--reference", required=True)
        command.add_argument("--state", default=".witness", help="directory for enrollment records")
        command.add_argument("--json", action="store_true", help="print the verdict as JSON")
        command.add_argument("--save", metavar="FILE", help="also save the nonce and raw attestation (evidence)")
        if name == "enroll":
            command.add_argument("--force", action="store_true", help="replace an existing enrollment")

    dashboard = commands.add_parser("dashboard", help="serve the fleet dashboard (re-verifies every --interval s)")
    dashboard.add_argument("-r", "--reference", help="reference.json (replay: defaults to DIR/reference.json)")
    dashboard.add_argument("--state", default=".witness", help="directory for enrollment records")
    dashboard.add_argument("--device", action="append", default=[], metavar="NAME=HOST:PORT")
    dashboard.add_argument("--replay", metavar="DIR", help="serve captured attestation-*.json, verified offline")
    dashboard.add_argument("--environment", help="environment label shown on the page, e.g. 'QEMU, software TPM'")
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", type=int, default=8650)
    dashboard.add_argument("--interval", type=float, default=10.0, help="seconds between re-verifications")

    args = parser.parse_args(argv)
    if args.command == "dashboard":
        if not 1.0 <= args.interval <= 3600.0:  # also rejects nan
            parser.error("--interval must be between 1 and 3600 seconds")
        from .dashboard import live_fleet, replay_fleet, serve
        if args.replay:
            fleet = replay_fleet(args.replay, args.reference, args.interval, args.environment)
        elif args.reference and args.device:
            fleet = live_fleet(args.reference, args.state, args.device, args.interval, args.environment)
        else:
            parser.error("dashboard needs --replay DIR, or -r reference.json and at least one --device")
        serve(fleet, args.host, args.port)
        return 0
    if args.command == "release-key":
        from .release import load_release_key, make_release_key, public_xy
        make_release_key(args.path)
        x, y = public_xy(load_release_key(args.path))
        with open(args.path + ".pub", "w") as out:  # goes into the IFS as /proc/boot/witness-release.pub
            out.write(f"release_x {x.hex()}\nrelease_y {y.hex()}\n")
        print(f"wrote {args.path} (keep it on the build host) and {args.path}.pub (for the image)")
        return 0
    if args.command == "reference":
        result = build_reference(args.image_dir, dict(item.split("=", 1) for item in args.replace))
        if args.release_key:
            from .release import load_release_key, policy_file_text, sign_release
            policy = sign_release(result, load_release_key(args.release_key))
            result["release"] = {k: policy[k] for k in ("pcr_mask", "approved_policy", "release_x", "release_y")}
            with open(args.output + ".policy", "w") as out:
                out.write(policy_file_text(policy))
            print(f"wrote {args.output}.policy: release PCR policy signed for PCR 4,5,8,9")
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
    try:
        attestation = request_attestation(args.device, nonce)
    except (OSError, ValueError) as error:  # unreachable or not JSON: no evidence, not trusted
        print(f"{BOLD}{args.device}{RESET}  {RED}{BOLD}NOT TRUSTED{RESET}   no attestation: {error}")
        return 2
    if args.save:
        with open(args.save, "w") as out:
            json.dump({"nonce": nonce.hex(), "attestation": attestation}, out, indent=1)

    if args.command == "enroll":
        if os.path.exists(path) and not args.force:
            print(f"{RED}{args.device} is already enrolled ({path}); use --force to replace it{RESET}")
            return 1
        verdict = appraise(attestation, nonce, reference_values, None, enrolling=True)
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
