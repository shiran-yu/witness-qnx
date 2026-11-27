#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# A three-device fleet on one host, each QEMU VM with its own software TPM, all on the current release:
#   gateway-a  the device from demo.sh, on release v2            -> TRUSTED
#   gateway-b  rolled back to the genuinely signed v1            -> NOT TRUSTED, the TPM refuses its key
#   gateway-c  a modified TPM library planted                    -> NOT TRUSTED, names the file
# Run after: demo.sh build up enroll update (gateway-a at v2). Then open the dashboard it prints.
#
#   fleet.sh up        clone gateway-a's disk into two new devices with fresh TPMs, enroll them, apply the scenes
#   fleet.sh dashboard serve the fleet dashboard on http://127.0.0.1:8650
#   fleet.sh down      power off the two clones (gateway-a: demo.sh down)
set -euo pipefail

SRC=$(cd "$(dirname "$0")/.." && pwd)
WORK=${WORK:-$SRC/.work}
DEMO=$SRC/demo/demo.sh
CLONES=("b:10032" "c:10042")  # name:ssh port (attestation on port+1)

clone_image() {  # same disk and firmware, a new TPM: a second unit off the same production line
    local dir=$1
    rm -rf "$dir"
    mkdir -p "$dir/output"
    cp -r "$WORK/vm/output/." "$dir/output/"
    cp "$WORK/vm/ovmf_vars.fd" "$dir/"
    rm -f "$dir/output/qemu.pid" "$dir/output/console.log"
}

case "${1:-}" in
up)
    [ -f "$WORK/reference-v1.json" ] || { echo "run demo.sh build up enroll update first" >&2; exit 1; }
    # a consistent copy of gateway-a's disk: power it off while copying
    SSH_PORT=10022 "$DEMO" down
    for spec in "${CLONES[@]}"; do clone_image "$WORK/vm-${spec%%:*}"; done
    SSH_PORT=10022 "$DEMO" up >/dev/null
    for spec in "${CLONES[@]}"; do
        name=${spec%%:*} port=${spec#*:}
        export IMAGE=$WORK/vm-$name SSH_PORT=$port
        echo "==> gateway-$name: first boot with its own TPM; the copied device key belongs to gateway-a's TPM"
        "$DEMO" up >/dev/null
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i "$WORK/id_ed25519" \
            -p "$port" root@127.0.0.1 'rm -f /data/var/witness/device-key.blob; sync; shutdown -b' >/dev/null 2>&1 || true
        sleep 5
        (cd "$IMAGE" && "$SRC/scripts/vm.sh" stop >/dev/null)
        "$DEMO" up >/dev/null  # provisions a key in this TPM; the v2 policy is already on its disk
        grep -a 'witnessd: ' "$IMAGE/output/console.log" | tr -d '\r' | grep -E 'provisioned|recorded|released' || true
        "$DEMO" enroll | tail -1
    done
    echo "==> gateway-b: roll back to v1"
    IMAGE=$WORK/vm-b SSH_PORT=10032 "$DEMO" rollback | grep -E '^==>|^127|FAIL' || true
    echo "==> gateway-c: plant a modified TPM library"
    IMAGE=$WORK/vm-c SSH_PORT=10042 "$DEMO" tamper lib | grep -E '^==>' || true
    "$0" dashboard-hint
    ;;
dashboard-hint)
    echo "fleet.sh dashboard  ->  http://127.0.0.1:8650"
    ;;
dashboard)
    exec uv run --project "$SRC/host" witness dashboard -r "$WORK/reference.json" --state "$WORK/state" \
        --device gateway-a=127.0.0.1:10023 --device gateway-b=127.0.0.1:10033 --device gateway-c=127.0.0.1:10043 \
        --port "${PORT:-8650}"
    ;;
down)
    for spec in "${CLONES[@]}"; do
        IMAGE=$WORK/vm-${spec%%:*} SSH_PORT=${spec#*:} "$DEMO" down || true
    done
    ;;
*)
    sed -n '3,11p' "$0"
    exit 2
    ;;
esac
