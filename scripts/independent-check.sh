#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Check the captured fleet evidence with tools Witness did not write: tpm2-tools (tpm2_checkquote,
# tpm2_print) verifies each device's TPM quote (AK signature over the quote, the verifier's nonce),
# and sha256sum ties the reported PCR 0-9 values to the digest the TPM signed.
# Negative controls: a wrong nonce and a flipped byte in the quote must both be rejected.
# Needs: tpm2-tools (apt install tpm2-tools), python3. Env: TPM2_BIN (dir of the tpm2_* tools).
set -euo pipefail

SRC=$(cd "$(dirname "$0")/.." && pwd)
FIX=${1:-$SRC/host/tests/fixtures/fleet}
BIN=${TPM2_BIN:+$TPM2_BIN/}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fail=0

for f in "$FIX"/attestation-*.json; do
    name=$(basename "$f" .json); name=${name#attestation-}
    python3 - "$f" "$TMP" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1])); a, t = d["attestation"], sys.argv[2]
for k in ("ak_public", "quote", "signature"):
    open(f"{t}/{k}.bin", "wb").write(bytes.fromhex(a[k]))
bad = bytearray(bytes.fromhex(a["quote"])); bad[-1] ^= 1
open(f"{t}/quote-bad.bin", "wb").write(bad)
open(f"{t}/nonce", "w").write(d["nonce"])
open(f"{t}/pcrs.bin", "wb").write(b"".join(bytes.fromhex(a["pcrs"][str(i)]) for i in range(10)))
EOF
    nonce=$(cat "$TMP/nonce")
    check() { "${BIN}tpm2_checkquote" -u "$TMP/ak_public.bin" -s "$TMP/signature.bin" -g sha256 -m "$1" -q "$2" >/dev/null 2>&1; }
    signed=$("${BIN}tpm2_print" -t TPMS_ATTEST "$TMP/quote.bin" | awk '/pcrDigest:/ {print $2}')
    select=$("${BIN}tpm2_print" -t TPMS_ATTEST "$TMP/quote.bin" | awk '/pcrSelect: [0-9a-f]+$/ {print $2}')
    reported=$(sha256sum "$TMP/pcrs.bin" | cut -d' ' -f1)
    r1=FAIL r2=FAIL r3=FAIL r4=FAIL
    check "$TMP/quote.bin" "$nonce" && r1=ok
    check "$TMP/quote.bin" "00${nonce:2}" || r2=ok
    check "$TMP/quote-bad.bin" "$nonce" || r3=ok
    [ "$signed" = "$reported" ] && [ "$select" = ff0300 ] && r4=ok
    printf '%-10s quote signature + nonce: %-4s  wrong nonce rejected: %-4s  altered quote rejected: %-4s  PCR 0-9 = signed digest: %s\n' \
        "$name" "$r1" "$r2" "$r3" "$r4"
    [ "$r1$r2$r3$r4" = okokokok ] || fail=1
done
"${BIN}tpm2_checkquote" --version 2>/dev/null | head -1 || true
exit $fail
