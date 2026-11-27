#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Witness golden path on QEMU. Requires: QNX SDP 8.0 env sourced, qemu-system-x86_64, swtpm, OVMF, uv.
#
#   demo.sh build      cross-build Witness, create a UEFI QNX 8.0 image with the Witness layer
#   demo.sh up         boot it headless with a software TPM (swtpm) on the TIS interface
#   demo.sh enroll     record the device's attestation key and firmware baseline (known-good boot)
#   demo.sh verify     challenge the device and appraise its boot against the release
#   demo.sh tamper [config|app|lib|data]  modify the device the way an attacker would, then reboot
#   demo.sh restore    undo the tamper (or a rollback: reinstall the current release), reboot
#   demo.sh update     signed release v2 (one hardened file), installed as an update agent would (here over ssh);
#                      the device keeps its key
#   demo.sh rollback   reinstall release v1 and its genuine signed policy (the TPM refuses it)
#   demo.sh down       power off
#   demo.sh attack     as root on the device, try to use the TPM directly (denied by the security policy)
# Env: WORK (default src/.work), IMAGE ($WORK/vm), SSH_PORT (10022; attestation on SSH_PORT+1), SECPOL (secure|no)
set -euo pipefail

SRC=$(cd "$(dirname "$0")/.." && pwd)
WORK=${WORK:-$SRC/.work}
IMAGE=${IMAGE:-$WORK/vm}  # another device: a copy of the image dir with its own tpmstate (demo/fleet.sh)
SSH_PORT=${SSH_PORT:-10022}
SECPOL=${SECPOL:-secure}  # secure: QNX security policy image/witness.secpol; no: unconfined (applies when the image is created)
DEVICE=127.0.0.1:$((SSH_PORT + 1))
KEY=${WITNESS_SSH_KEY:-$WORK/id_ed25519}
SSH=(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 -i "$KEY" -p "$SSH_PORT" root@127.0.0.1)
WITNESS=(uv run --project "$SRC/host" witness)
RELEASE_KEY=${RELEASE_KEY:-$WORK/release-key.pem}

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

# the signed policy of the current release, delivered the way an update agent would (it is signed, not measured)
push_release_policy() {
    say "delivering the signed release policy to /data/var/witness/release-policy"
    "${SSH[@]}" 'mkdir -p /data/var/witness && cat > /data/var/witness/release-policy' < "$WORK/reference.json.policy"
}

# release numbers only go up: the swtpm state (and its anti-rollback NV bits) outlives rebuilds
# (demo names v1/v2 are the two most recent numbers; sets RELEASE_NUMBER, no subshell so exit stops the script)
next_release_number() {
    RELEASE_NUMBER=$(( $(cat "$WORK/release-number" 2>/dev/null || echo 0) + 1 ))
    [ "$RELEASE_NUMBER" -le 63 ] || { echo "release numbers used up (63): for a new TPM remove both $IMAGE/tpmstate and $WORK/release-number" >&2; exit 1; }
    echo "$RELEASE_NUMBER" > "$WORK/release-number"
}

reboot_device() {
    "${SSH[@]}" 'sync; shutdown -b' >/dev/null 2>&1 || true
    sleep 5
    (cd "$IMAGE" && "$SRC/scripts/vm.sh" stop && SSH_PORT=$SSH_PORT "$SRC/scripts/vm.sh" start)
    wait_for_agent
}

# several steps in one call: demo.sh build up enroll verify ("tamper lib" as one quoted word)
if [ $# -gt 1 ] && [ "$1" != tamper ]; then
    for step in "$@"; do "$0" $step || exit $?; done
    exit 0
fi

case "${1:-}" in
build)
    command -v mkqnximage >/dev/null || { echo "source qnxsdp-env.sh first" >&2; exit 1; }
    mkdir -p "$WORK"
    rm -f "$WORK/reference-v1.json" "$WORK/reference-v1.json.policy"  # a fresh build is release v1 again
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
    # release signing key: stays on the build host; its public half goes into the IFS
    [ -f "$RELEASE_KEY" ] || "${WITNESS[@]}" release-key "$RELEASE_KEY" >/dev/null
    WITNESS_RELEASE_PUB="$RELEASE_KEY.pub" "$SRC/image/witness-image.sh" "$IMAGE" >/dev/null
    (cd "$IMAGE" && mkqnximage --build >"$WORK/build.log" 2>&1) || { tail "$WORK/build.log"; exit 1; }
    say "computing reference values from the build output and signing the release"
    next_release_number
    "${WITNESS[@]}" reference "$IMAGE" -o "$WORK/reference.json" --release-key "$RELEASE_KEY" --release-number "$RELEASE_NUMBER"
    ;;
up)
    (cd "$IMAGE" && SSH_PORT=$SSH_PORT "$SRC/scripts/vm.sh" start)
    say "waiting for witnessd"
    wait_for_agent
    push_release_policy
    grep -a -E 'Witness|witnessd' "$IMAGE/output/console.log" | tr -d '\r' || true
    ;;
enroll)
    # --force: each build provisions a new device key, so the demo re-enrolls on purpose
    "${WITNESS[@]}" enroll --force --device "$DEVICE" -r "$WORK/reference.json" --state "$WORK/state"
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
    lib)
        say "attacker plants a modified TPM library that witnessd loads"
        "${SSH[@]}" 'cp -n /system/lib/libtss2-rc.so.1 /data/var/witness/libtss2-rc.so.1.orig 2>/dev/null || true;
                     cp /system/lib/libtss2-rc.so.1 /system/lib/.rc.new && echo "# patched" >> /system/lib/.rc.new &&
                     mv /system/lib/.rc.new /system/lib/libtss2-rc.so.1'
        ;;
    data)
        say "attacker appends a command to /etc/settings/network, which the boot script runs as root"
        "${SSH[@]}" 'cp -n /data/var/etc/settings/network /data/var/witness/network.orig 2>/dev/null || true;
                     echo "touch /data/var/witness/injected-command-ran" >> /data/var/etc/settings/network'
        ;;
    *) echo "tamper: config|app|lib|data" >&2; exit 2 ;;
    esac
    say "rebooting"
    reboot_device
    ;;
restore)
    say "restoring the released files"
    "${SSH[@]}" 'rm -f /data/var/witness/injected-command-ran;
                 for f in sshd_config:/system/etc/ssh/sshd_config witnessd:/system/bin/witnessd libtss2-rc.so.1:/system/lib/libtss2-rc.so.1 network:/data/var/etc/settings/network; do
                     o=/data/var/witness/${f%%:*}.orig; t=${f#*:};
                     [ -f $o ] && cp $o $t.restore && mv $t.restore $t && rm $o; done; true'
    if [ -f "$WORK/reference-v1.json" ]; then  # at release v2: reinstall it (undoes a rollback)
        "${SSH[@]}" 'cat > /system/etc/ssh/.sshd_config.new && mv /system/etc/ssh/.sshd_config.new /system/etc/ssh/sshd_config' \
            < "$WORK/release-v2/sshd_config"
        push_release_policy
    fi
    reboot_device
    ;;
update)
    # release v2 = the released build plus one hardened file; the device keeps its key (no re-provisioning)
    [ ! -f "$WORK/reference-v1.json" ] || { echo "already at release v2; demo.sh build starts again from v1" >&2; exit 1; }
    say "build host: release v2 hardens sshd (MaxAuthTries 3); reference computed and signed with the release key"
    mkdir -p "$WORK/release-v1" "$WORK/release-v2"
    "${SSH[@]}" 'cat /system/etc/ssh/sshd_config' > "$WORK/release-v1/sshd_config"
    cp "$WORK/release-v1/sshd_config" "$WORK/release-v2/sshd_config"
    python3 -c 'import hashlib,json,sys; r=json.load(open(sys.argv[1]))["files"]["/system/etc/ssh/sshd_config"]
sys.exit(hashlib.sha256(open(sys.argv[2],"rb").read()).hexdigest() != r)' "$WORK/reference.json" "$WORK/release-v2/sshd_config" \
        || { echo "sshd_config on the device is not the released one; restore first" >&2; exit 1; }
    echo "MaxAuthTries 3" >> "$WORK/release-v2/sshd_config"
    next_release_number
    "${WITNESS[@]}" reference "$IMAGE" -o "$WORK/reference-v2.json" --release-key "$RELEASE_KEY" --release-number "$RELEASE_NUMBER" \
        --previous "$WORK/reference.json" --replace /system/etc/ssh/sshd_config="$WORK/release-v2/sshd_config"
    cp "$WORK/reference.json" "$WORK/reference-v1.json" && cp "$WORK/reference.json.policy" "$WORK/reference-v1.json.policy"
    cp "$WORK/reference-v2.json" "$WORK/reference.json" && cp "$WORK/reference-v2.json.policy" "$WORK/reference.json.policy"
    say "device: the update agent installs the file and the signed v2 policy, then reboots"
    "${SSH[@]}" 'cat > /system/etc/ssh/.sshd_config.new && mv /system/etc/ssh/.sshd_config.new /system/etc/ssh/sshd_config' \
        < "$WORK/release-v2/sshd_config"
    push_release_policy
    reboot_device
    grep -a 'witnessd: release' "$IMAGE/output/console.log" | tr -d '\r' || true  # "release N recorded"
    ;;
rollback)
    # v1 is genuinely signed, but v2 has run: the TPM's anti-rollback NV bits refuse v1's policy
    [ -f "$WORK/reference-v1.json" ] || { echo "rollback needs demo.sh update first" >&2; exit 1; }
    say "attacker reinstalls release v1 (the old sshd_config) and its genuine signed policy"
    "${SSH[@]}" 'cat > /system/etc/ssh/.sshd_config.new && mv /system/etc/ssh/.sshd_config.new /system/etc/ssh/sshd_config' \
        < "$WORK/release-v1/sshd_config"
    "${SSH[@]}" 'cat > /data/var/witness/release-policy' < "$WORK/reference-v1.json.policy"
    say "rebooting"
    reboot_device
    say "checked against release v1's own reference: every measurement matches v1, and the TPM still refuses the key"
    "${WITNESS[@]}" verify --device "$DEVICE" -r "$WORK/reference-v1.json" --state "$WORK/state" || true
    grep -a 'witnessd: ' "$IMAGE/output/console.log" | tr -d '\r' | tail -3
    ;;
attack)
    say "root on the device tries to extend PCR 8, run its own agent with the agent's type, borrow the measurer's type, have the device key sign a fleet report, and plant a boot hook"
    "${SSH[@]}" 'for c in "tpm-raw 80020000004100000182000000080000000940000009000000000000000001000b$(printf %064d 0)" \
                          "on -T witnessd_t /system/bin/witnessd -f -p 7651" \
                          "on -T witness_measure_t /proc/boot/witness-measure -p 8 -s forged" \
                          "witness-report -c" \
                          "echo touch /tmp/pwned > /boot/onboot"; do
                     echo "# $c"; sh -c "$c" 2>&1 && echo "  ALLOWED" || echo "  denied"; done'
    # the driver, the agent and the report app run as uid 70: root may not open their memory for writing
    "${SSH[@]}" 'for n in dev-tpm-tis witnessd witness-report; do
                     p=$(pidin -f an | awk -v n="$n" "\$2 ~ (\"/\" n \"\$\") || \$2 == n {print \$1; exit}");
                     echo "# exec 3<>/proc/$p/as      (write the memory of $n)";
                     sh -c "exec 3<>/proc/$p/as" 2>&1 && echo "  ALLOWED" || echo "  denied"; done'
    # root may write /system/lib and signal the agent: swap the TPM library, kill the agent, see what its supervisor restarts
    # (a library the agent maps; writing it in place is refused while mapped, so rename over it)
    "${SSH[@]}" 'l=/system/lib/libtss2-esys.so.1; cp $l /data/var/witness/esys.orig;
                 echo "# swap $l, then kill the agent so its supervisor restarts it";
                 cp $l $l.new && echo "# patched" >> $l.new && mv $l.new $l;
                 maps() { pidin -p $1 mem | grep -o "[^ /]*\.so[.0-9]*" | sort -u; };
                 # supervisor: the witnessd started by the boot script (parent 1); agent: its child, chosen by parent, never by pid order
                 child() { pidin -f aen | awk -v p=$1 "\$3 ~ /witnessd\$/ && \$2 == p {print \$1}"; };
                 s=$(child 1); old=$(child $s); a=; rc=0;
                 if [ -n "$s" ] && [ -n "$old" ]; then kill $old;
                     for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do a=$(child $s); [ -n "$a" ] && [ "$a" != "$old" ] && break; a=; sleep 1; done; fi;
                 if [ -z "$a" ]; then echo "  check not run: no restarted agent under supervisor $s within 25 s"; rc=1;
                 elif [ "$(maps $a)" != "$(maps $s)" ]; then echo "  ALLOWED: restarted agent $a maps objects its supervisor $s did not load";
                 else echo "  no effect: restarted agent $a is a fork of supervisor $s (no exec), mapping the same $(maps $s | wc -l | tr -d " ") objects it loaded at the measured launch"; fi;
                 cp /data/var/witness/esys.orig $l.new && mv $l.new $l && rm /data/var/witness/esys.orig; exit $rc'
    ;;
down)
    "${SSH[@]}" 'shutdown' >/dev/null 2>&1 || true
    sleep 2
    (cd "$IMAGE" && "$SRC/scripts/vm.sh" stop)
    ;;
*)
    sed -n '3,16p' "$0"
    exit 2
    ;;
esac
