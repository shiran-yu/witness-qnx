#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Witness golden path on QEMU. Requires: QNX SDP 8.0 env sourced, qemu-system-x86_64, swtpm, OVMF, uv.
#
#   demo.sh build      cross-build Witness, create a UEFI QNX 8.0 image with the Witness layer
#   demo.sh up         boot it headless with a software TPM (swtpm) on the TIS interface
#   demo.sh enroll     record the device's attestation key and firmware baseline (known-good boot)
#   demo.sh verify     challenge the device and appraise its boot against the release
#   demo.sh tamper [config|app]   modify the device the way an attacker would, then reboot
#   demo.sh restore    undo the tamper, reboot
#   demo.sh down       power off
#   demo.sh attack     as root on the device, try to use the TPM directly (denied by the security policy)
# Env: WORK (default src/.work), SSH_PORT (10022; attestation on SSH_PORT+1), SECPOL (secure|no)
set -euo pipefail

SRC=$(cd "$(dirname "$0")/.." && pwd)
WORK=${WORK:-$SRC/.work}
IMAGE=$WORK/vm
SSH_PORT=${SSH_PORT:-10022}
SECPOL=${SECPOL:-secure}  # secure: QNX security policy image/witness.secpol; no: unconfined (applies when the image is created)
DEVICE=127.0.0.1:$((SSH_PORT + 1))
KEY=${WITNESS_SSH_KEY:-$WORK/id_ed25519}
SSH=(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 -i "$KEY" -p "$SSH_PORT" root@127.0.0.1)
WITNESS=(uv run --project "$SRC/host" witness)

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }

wait_for_agent() {
    for _ in $(seq 90); do
        if python3 - "$DEVICE" <<'EOF' 2>/dev/null; then return 0; fi
import socket, sys
host, port = sys.argv[1].rsplit(":", 1)
s = socket.create_connection((host, int(port)), timeout=2)
s.sendall(b"PING\n")
sys.exit(0 if s.recv(1) else 1)
EOF
        sleep 1
    done
    echo "witnessd did not come up; see $IMAGE/output/console.log" >&2
    return 1
}

reboot_device() {
    "${SSH[@]}" 'sync; shutdown -b' >/dev/null 2>&1 || true
    sleep 5
    (cd "$IMAGE" && "$SRC/scripts/vm.sh" stop && SSH_PORT=$SSH_PORT "$SRC/scripts/vm.sh" start)
    wait_for_agent
}

case "${1:-}" in
build)
    command -v mkqnximage >/dev/null || { echo "source qnxsdp-env.sh first" >&2; exit 1; }
    mkdir -p "$WORK"
    [ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N "" -f "$KEY"
    say "cross-building Witness for QNX 8.0 x86_64"
    make -C "$SRC" -s
    say "creating a UEFI QNX 8.0 image with the Witness layer"
    if [ ! -d "$IMAGE" ]; then
        mkdir -p "$IMAGE"
        secpol=(--secpol=no)
        [ "$SECPOL" = secure ] && secpol=(--secpol=secure --policy="$SRC/image/witness.secpol")
        (cd "$IMAGE" && mkqnximage --type=qemu --arch=x86_64 --boot-mode=uefi "${secpol[@]}" --ip=dhcp --cpu=2 --ram=1G \
            --ssh-ident="$KEY.pub" --noprompt >/dev/null)
    fi
    "$SRC/image/witness-image.sh" "$IMAGE" >/dev/null
    (cd "$IMAGE" && mkqnximage --build >"$WORK/build.log" 2>&1) || { tail "$WORK/build.log"; exit 1; }
    say "computing reference values from the build output"
    "${WITNESS[@]}" reference "$IMAGE" -o "$WORK/reference.json"
    ;;
up)
    (cd "$IMAGE" && SSH_PORT=$SSH_PORT "$SRC/scripts/vm.sh" start)
    say "waiting for witnessd"
    wait_for_agent
    grep -a -E 'Witness|witnessd' "$IMAGE/output/console.log" | tr -d '\r' || true
    ;;
enroll)
    "${WITNESS[@]}" enroll --device "$DEVICE" -r "$WORK/reference.json" --state "$WORK/state"
    ;;
verify)
    "${WITNESS[@]}" verify --device "$DEVICE" -r "$WORK/reference.json" --state "$WORK/state"
    ;;
tamper)
    case "${2:-config}" in
    config)
        say "attacker enables password logins in /system/etc/ssh/sshd_config"
        "${SSH[@]}" 'cp -n /system/etc/ssh/sshd_config /data/var/witness/sshd_config.orig 2>/dev/null || true;
                     echo "PasswordAuthentication yes" >> /system/etc/ssh/sshd_config'
        ;;
    app)
        say "attacker swaps the attestation agent binary for a patched copy"
        # a running binary cannot be written; like a real attacker, write a patched copy and rename it over
        "${SSH[@]}" 'cp -n /system/bin/witnessd /data/var/witness/witnessd.orig 2>/dev/null || true;
                     cp /system/bin/witnessd /system/bin/.witnessd.new && echo "# patched" >> /system/bin/.witnessd.new &&
                     mv /system/bin/.witnessd.new /system/bin/witnessd'
        ;;
    *) echo "tamper: config|app" >&2; exit 2 ;;
    esac
    say "rebooting"
    reboot_device
    ;;
restore)
    say "restoring the released files"
    "${SSH[@]}" 'for f in sshd_config:/system/etc/ssh/sshd_config witnessd:/system/bin/witnessd; do
                     o=/data/var/witness/${f%%:*}.orig; t=${f#*:};
                     [ -f $o ] && cp $o $t.restore && mv $t.restore $t && rm $o; done; true'
    reboot_device
    ;;
attack)
    say "root on the device tries to extend PCR 8 back, use the resource manager, and borrow a measured type"
    "${SSH[@]}" 'for c in "tpm-raw 80020000004100000182000000080000000940000009000000000000000001000b$(printf %064d 0)" \
                          "env TPM_DEVICE=/dev/tpmrm0 tpm-raw 80010000000c0000017b0008" \
                          "on -T witness_measure_t /proc/boot/witness-measure -p 8 -s forged"; do
                     echo "# $c"; sh -c "$c" 2>&1 && echo "  ALLOWED" || echo "  denied"; done'
    ;;
down)
    "${SSH[@]}" 'shutdown' >/dev/null 2>&1 || true
    sleep 2
    (cd "$IMAGE" && "$SRC/scripts/vm.sh" stop)
    ;;
*)
    sed -n '3,14p' "$0"
    exit 2
    ;;
esac
