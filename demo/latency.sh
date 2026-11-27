#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Does attestation disturb control work? A 1 kHz SCHED_FIFO loop (tools/rt-probe) on the device, idle and
# while the host floods witnessd with attestation requests, with the loop above witnessd's priority 8
# (priority 10, QNX's default) and below it (7). Prints the period jitter of each run.
# Run on a booted device (demo.sh up). QEMU: absolute numbers include the host's noise; compare the rows.
# Env: SSH_PORT (10022), SECONDS_PER_RUN (30), CLIENTS (8)
set -euo pipefail

SRC=$(cd "$(dirname "$0")/.." && pwd)
WORK=${WORK:-$SRC/.work}
SSH_PORT=${SSH_PORT:-10022}
RUN=${SECONDS_PER_RUN:-30}
CLIENTS=${CLIENTS:-8}
DEVICE=127.0.0.1:$((SSH_PORT + 1))
SSH=(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i "$WORK/id_ed25519" -p "$SSH_PORT" root@127.0.0.1)

flood() {  # CLIENTS parallel request loops for $1 seconds; prints how many attestations completed
    uv run --project "$SRC/host" python - "$DEVICE" "$1" "$CLIENTS" <<'EOF'
import os, sys, threading, time
from witness.cli import request_attestation
device, seconds, clients = sys.argv[1], float(sys.argv[2]), int(sys.argv[3])
end, done, lock = time.monotonic() + seconds, [0], threading.Lock()
def loop():
    while time.monotonic() < end:
        try:
            request_attestation(device, os.urandom(32), timeout=10)
            with lock:
                done[0] += 1
        except Exception:
            pass
threads = [threading.Thread(target=loop) for _ in range(clients)]
[t.start() for t in threads]
[t.join() for t in threads]
print(f"  load: {done[0]} attestations ({done[0] / seconds:.1f}/s) from {clients} clients")
EOF
}

[ -x "$SRC/build/x86_64/rt-probe" ] || { echo "make first (build/x86_64/rt-probe)" >&2; exit 1; }
"${SSH[@]}" 'cat > /tmp/rt-probe && chmod 755 /tmp/rt-probe' < "$SRC/build/x86_64/rt-probe"
echo "1 kHz loop, $RUN s per run; witnessd and the TPM driver serve attestation at priority 8"
for priority in 10 7; do
    echo "==> loop at priority $priority, idle"
    "${SSH[@]}" "/tmp/rt-probe -p $priority -s $RUN"
    echo "==> loop at priority $priority, attestation flood"
    flood "$((RUN + 2))" &
    sleep 1
    "${SSH[@]}" "/tmp/rt-probe -p $priority -s $RUN"
    wait
done
