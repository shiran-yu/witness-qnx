#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Add the Witness layer to a mkqnximage image directory, through mkqnximage's own snippet mechanism:
#   IFS:       dev-tpm-tis, witness-measure, the measurement manifest (all covered by the firmware's PCR 4)
#   boot:      driver started in the IFS script; system partition measured into PCR 8 right after mount
#   system:    QNX TCG stack (tss2, tabrm, tpm2-tools), libtss2-tcti-witness, tabrm config, witnessd
#   post-start tabrm on /dev/tpmrm0 over our TCTI; application layer measured into PCR 9; witnessd
# Usage: witness-image.sh <image-dir>   then: (cd <image-dir> && mkqnximage --build)
set -euo pipefail

IMAGE_DIR=$(cd "${1:?usage: witness-image.sh <image-dir>}" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
BUILD="$ROOT/build/x86_64"
SNIPPETS="$IMAGE_DIR/local/snippets"

[ -d "$SNIPPETS" ] || { echo "witness-image: $IMAGE_DIR is not a mkqnximage directory (run mkqnximage once)" >&2; exit 1; }
for f in dev-tpm-tis witness-measure libtss2-tcti-witness.so.0 tpm-raw; do
    [ -f "$BUILD/$f" ] || { echo "witness-image: $BUILD/$f missing; run make first" >&2; exit 1; }
done

# 1. UEFI: IFS load address that current OVMF accepts (harmless for direct -kernel boots)
cp "$HERE/uefi/definitions.zz_witness" "$SNIPPETS/definitions.zz_witness"

# 2. IFS contents
cat > "$SNIPPETS/ifs_files.witness" <<EOF
#############################################
### Witness (IFS: measured by firmware into PCR 4 on UEFI targets)
#############################################
[perms=0555] dev-tpm-tis=$BUILD/dev-tpm-tis
[perms=0555] witness-measure=$BUILD/witness-measure
[perms=0444] witness.manifest=$HERE/witness.manifest
EOF

# 3. IFS script: start the driver before anything from the (not yet measured) system partition runs
cat > "$SNIPPETS/ifs_start.witness" <<'EOF'
    display_msg "---> Witness: starting TPM driver"
    dev-tpm-tis
    waitfor /dev/tpm0 5
EOF

# 4. startup.sh right after the file systems are mounted: measure before use
cat > "$SNIPPETS/startup_postfs.witness" <<'EOF'
echo "---> Witness: measuring system partition into PCR 8"
/proc/boot/witness-measure -p 8 -m /proc/boot/witness.manifest
/proc/boot/witness-measure -p 8 -t marker -s "witness:system-measured"
EOF

# 5. system partition: QNX TCG stack + Witness user space
cat > "$SNIPPETS/system_files.witness" <<EOF
#############################################
### QNX TCG stack (SDP package security.tcg) + Witness
#############################################
lib/libtss2-esys.so.1=usr/lib/libtss2-esys.so.1
lib/libtss2-mu.so.1=usr/lib/libtss2-mu.so.1
lib/libtss2-sys.so.1=usr/lib/libtss2-sys.so.1
lib/libtss2-rc.so.1=usr/lib/libtss2-rc.so.1
lib/libtss2-tctildr.so.1=usr/lib/libtss2-tctildr.so.1
lib/libtss2_helper.so.1=lib/libtss2_helper.so.1
lib/libtcti_tabrm.so.1=lib/libtcti_tabrm.so.1
lib/dll/tabrm_rm_mod_intel.so=lib/dll/tabrm_rm_mod_intel.so
[perms=0555] bin/tabrm=sbin/tabrm
[perms=0555] bin/tpm2_getrandom=usr/bin/tpm2_getrandom
[perms=0555] bin/tpm2_getcap=usr/bin/tpm2_getcap
[perms=0555] bin/tpm2_pcrread=usr/bin/tpm2_pcrread
[perms=0555] bin/tpm2_pcrextend=usr/bin/tpm2_pcrextend
[perms=0555] bin/tpm2_createek=usr/bin/tpm2_createek
[perms=0555] bin/tpm2_createak=usr/bin/tpm2_createak
[perms=0555] bin/tpm2_createprimary=usr/bin/tpm2_createprimary
[perms=0555] bin/tpm2_quote=usr/bin/tpm2_quote
[perms=0555] bin/tpm2_readpublic=usr/bin/tpm2_readpublic
[perms=0555] bin/tpm2_flushcontext=usr/bin/tpm2_flushcontext
[perms=0555] bin/tpm2_startup=usr/bin/tpm2_startup
lib/libtss2-tcti-witness.so.0=$BUILD/libtss2-tcti-witness.so.0
[perms=0555] bin/tpm-raw=$BUILD/tpm-raw
[perms=0444] etc/witness/tabrm.cfg=$HERE/tabrm.cfg
EOF

# 6. post start: resource manager over our TCTI
cat > "$SNIPPETS/post_start.witness" <<'EOF'
echo "---> Witness: starting tabrm (/dev/tpmrm0) over libtss2-tcti-witness"
tabrm -C /system/etc/witness/tabrm.cfg
waitfor /dev/tpmrm0 5
EOF

echo "witness-image: snippets written to $SNIPPETS"
ls "$SNIPPETS" | grep -E 'witness'
