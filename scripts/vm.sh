#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Boot a mkqnximage QEMU x86_64 image headless with a software TPM (swtpm) on the TIS interface.
# Usage: vm.sh start|stop|status|console  (run from the mkqnximage image directory, or set VM_DIR)
# Env: SSH_PORT (10022), TPM=tis|none, KVM=auto|yes|no, SWTPM, QEMU, QEMU_EXTRA
set -euo pipefail

VM_DIR=${VM_DIR:-$PWD}
SSH_PORT=${SSH_PORT:-10022}
TPM=${TPM:-tis}
KVM=${KVM:-auto}
QEMU=${QEMU:-qemu-system-x86_64}
SWTPM=${SWTPM:-swtpm}
STATE="$VM_DIR/tpmstate"
OUT="$VM_DIR/output"
PIDF="$OUT/qemu.pid"

die() { echo "vm.sh: $*" >&2; exit 1; }

start() {
    [ -f "$OUT/ifs.bin" ] || die "no $OUT/ifs.bin; build the image with mkqnximage first"
    status >/dev/null 2>&1 && die "already running (pid $(cat "$PIDF"))"
    local accel=(-cpu max)
    if [ "$KVM" = yes ] || { [ "$KVM" = auto ] && [ -w /dev/kvm ]; }; then
        accel=(-enable-kvm -cpu host)
    fi
    local tpm=()
    if [ "$TPM" = tis ]; then
        mkdir -p "$STATE"
        # swtpm exits when QEMU disconnects; state (EK, NV) persists in $STATE across boots
        "$SWTPM" socket --tpm2 --tpmstate dir="$STATE" --ctrl type=unixio,path="$STATE/sock" \
            --log file="$STATE/swtpm.log",level=2 --daemon
        for _ in $(seq 50); do [ -S "$STATE/sock" ] && break; sleep 0.1; done
        tpm=(-chardev socket,id=chrtpm,path="$STATE/sock" -tpmdev emulator,id=tpm0,chardev=chrtpm
             -device tpm-tis,tpmdev=tpm0)
    fi
    "$QEMU" "${accel[@]}" -smp 2 -m 1G -display none -no-reboot \
        -kernel "$OUT/ifs.bin" -drive file="$OUT/disk-qemu",format=raw,if=ide,id=drv0 \
        -netdev user,id=net0,hostfwd=tcp:127.0.0.1:"$SSH_PORT"-:22,hostfwd=tcp:127.0.0.1:$((SSH_PORT + 1))-:7650 \
        -device virtio-net-pci,netdev=net0 \
        -object rng-random,filename=/dev/urandom,id=rng0 -device virtio-rng-pci,rng=rng0 \
        "${tpm[@]}" -serial file:"$OUT/console.log" -pidfile "$PIDF" -daemonize ${QEMU_EXTRA:-}
    echo "started: ssh -p $SSH_PORT root@127.0.0.1 (console: $OUT/console.log, accel: ${accel[*]})"
}

stop() {
    [ -f "$PIDF" ] && kill "$(cat "$PIDF")" 2>/dev/null || true
    rm -f "$PIDF"
}

status() {
    [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null && { echo "running pid $(cat "$PIDF")"; return 0; }
    echo "stopped"; return 1
}

case "${1:-}" in
    start) start ;;
    stop) stop ;;
    status) status ;;
    console) tail -f "$OUT/console.log" ;;
    *) die "usage: vm.sh start|stop|status|console" ;;
esac
