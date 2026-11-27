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
BOOT=${BOOT:-$( [ -f "$VM_DIR/output/build/boot_part.build" ] && grep -q BOOTx64.EFI "$VM_DIR/output/build/boot_part.build" && echo uefi || echo kernel)}
OVMF_CODE=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}
OVMF_VARS=${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}
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
        stop_swtpm  # a swtpm left from a crashed run would share this state directory
        # state (EK, NV) persists in $STATE across boots; the log is per boot
        "$SWTPM" socket --tpm2 --tpmstate dir="$STATE" --ctrl type=unixio,path="$STATE/sock" \
            --log file="$STATE/swtpm.log",level=1,truncate --pid file="$STATE/swtpm.pid" --daemon
        for _ in $(seq 50); do [ -S "$STATE/sock" ] && break; sleep 0.1; done
        [ -S "$STATE/sock" ] || die "swtpm did not start (socket path must be < 108 chars; see $STATE/swtpm.log)"
        tpm=(-chardev socket,id=chrtpm,path="$STATE/sock" -tpmdev emulator,id=tpm0,chardev=chrtpm
             -device tpm-tis,tpmdev=tpm0)
    fi
    local boot=(-kernel "$OUT/ifs.bin")
    if [ "$BOOT" = uefi ]; then
        # UEFI firmware loads the IFS as EFI/BOOT/BOOTx64.EFI and measures it into PCR 4 (static root of trust)
        [ -f "$VM_DIR/ovmf_vars.fd" ] || cp "$OVMF_VARS" "$VM_DIR/ovmf_vars.fd"
        boot=(-drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" -drive if=pflash,format=raw,file="$VM_DIR/ovmf_vars.fd")
    fi
    "$QEMU" "${accel[@]}" -smp 2 -m 1G -display none -no-reboot \
        "${boot[@]}" -drive file="$OUT/disk-qemu",format=raw,if=ide,id=drv0 \
        -netdev user,id=net0,hostfwd=tcp:127.0.0.1:"$SSH_PORT"-:22,hostfwd=tcp:127.0.0.1:$((SSH_PORT + 1))-:7650 \
        -device virtio-net-pci,netdev=net0 \
        -object rng-random,filename=/dev/urandom,id=rng0 -device virtio-rng-pci,rng=rng0 \
        "${tpm[@]}" -serial file:"$OUT/console.log" -pidfile "$PIDF" -daemonize ${QEMU_EXTRA:-}
    echo "started: ssh -p $SSH_PORT root@127.0.0.1 (console: $OUT/console.log, accel: ${accel[*]})"
}

stop_swtpm() {
    [ -f "$STATE/swtpm.pid" ] && kill "$(cat "$STATE/swtpm.pid")" 2>/dev/null || true
    rm -f "$STATE/swtpm.pid"
}

stop() {
    [ -f "$PIDF" ] && kill "$(cat "$PIDF")" 2>/dev/null || true
    rm -f "$PIDF"
    sleep 0.5
    stop_swtpm
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
