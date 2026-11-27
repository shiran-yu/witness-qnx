#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Add the Witness layer to a mkqnximage image directory, through mkqnximage's own snippet mechanism:
#   IFS:       dev-tpm-tis, witness-measure, the application manifest (all covered by the firmware's PCR 4)
#   boot:      driver started in the IFS script; every file and symlink on /system measured into PCR 8 right after mount
#   system:    QNX TCG stack (tss2 ESYS/MU/RC/tctildr), libtss2-tcti-witness, witnessd
#   post-start application layer measured into PCR 9; witnessd (ESYS over our TCTI to /dev/tpm0)
# Usage: witness-image.sh <image-dir>   then: (cd <image-dir> && mkqnximage --build)
set -euo pipefail

IMAGE_DIR=$(cd "${1:?usage: witness-image.sh <image-dir>}" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
BUILD="$ROOT/build/x86_64"
SNIPPETS="$IMAGE_DIR/local/snippets"

[ -d "$SNIPPETS" ] || { echo "witness-image: $IMAGE_DIR is not a mkqnximage directory (run mkqnximage once)" >&2; exit 1; }
for f in dev-tpm-tis witness-measure libtss2-tcti-witness.so.0 tpm-raw witnessd witness-report; do
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
[perms=0444] witness-apps.manifest=$HERE/witness-apps.manifest
EOF
# release public key: the device key then follows signed releases (PolicyAuthorize) instead of one PCR state
if [ -n "${WITNESS_RELEASE_PUB:-}" ]; then
    echo "[perms=0444] witness-release.pub=$WITNESS_RELEASE_PUB" >> "$SNIPPETS/ifs_files.witness"
fi

# 3. IFS script: start the driver before anything from the (not yet measured) system partition runs
cat > "$SNIPPETS/ifs_start.witness" <<'EOF'
    display_msg "---> Witness: starting TPM driver"
    START_P(tpm_driver_t) dev-tpm-tis -i 5
    waitfor /dev/tpm0 5
EOF

# 4a. before devb: the stock mount_fs.sh runs /boot/onboot (unmeasured EFI partition) and
# /system/bin/cleanup_tmp before anything is measured. It exits early when /system and /data
# exist, so placeholders make it a no-op and 4b mounts the partitions itself.
cat > "$SNIPPETS/startup_postpci.witness" <<'EOF'
ln -sP /dev/null /system
ln -sP /dev/null /data
EOF

# 4b. replaces mount_fs.sh: mount, measure before use, then run what mount_fs.sh would have run
cat > "$SNIPPETS/startup_postfs.witness" <<'EOF'
rm /system /data
mount -t qnx6 -o noatime /dev/hd0.qnx6.1 /system
mount -t qnx6 /dev/hd0.qnx6.2 /data
echo "---> Witness: measuring system partition and boot configuration into PCR 8"
START_P(witness_measure_t) /proc/boot/witness-measure -p 8 -r /system
# /etc is /data/var/etc: start_net.sh sources settings/network as shell code, sshd reads passwd/shadow
START_P(witness_measure_t) /proc/boot/witness-measure -p 8 -r /data/var/etc
START_P(witness_measure_t) /proc/boot/witness-measure -p 8 -t marker -s "witness:system-measured"
# EFI partition read-only, and no onboot hook: nothing on it runs
mount -t dos -r /dev/hd0.efi.0 /boot
/system/bin/cleanup_tmp
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
lib/libtss2-tcti-witness.so.0=$BUILD/libtss2-tcti-witness.so.0
[perms=0555] bin/tpm-raw=$BUILD/tpm-raw
[perms=0555] bin/witnessd=$BUILD/witnessd
[perms=0555] bin/witness-report=$BUILD/witness-report
EOF

# 6. post start: application layer measured into PCR 9, then started. witnessd is the only TPM client
# after boot, through our TCTI straight to /dev/tpm0 (QNX's tabrm lost a request under load twice).
cat > "$SNIPPETS/post_start.witness" <<'EOF'
echo "---> Witness: measuring applications into PCR 9"
START_P(witness_measure_t) /proc/boot/witness-measure -p 9 -m /proc/boot/witness-apps.manifest
echo "---> Witness: starting attestation agent (port 7650)"
START_P(witnessd_t) witnessd
echo "---> Witness: starting signed fleet reports (to the host, 10.0.2.2:8650)"
START_P(witness_report_t) witness-report
EOF

echo "witness-image: snippets written to $SNIPPETS"
ls "$SNIPPETS" | grep -E 'witness'
