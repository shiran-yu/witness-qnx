# Witness: measured boot and remote attestation for QNX 8.0

A fleet operator cannot see what a QNX device in the field actually booted. A changed binary or a
changed config file on a gateway, a robot controller or an infusion pump looks the same from the
outside until it misbehaves.

Witness gives a QNX 8.0 target a TPM 2.0 root of trust and lets a remote verifier answer, with a
signature from the TPM, three questions:

1. **Is this the image we released?** UEFI firmware measures the QNX IFS (boot image) into PCR 4.
2. **Are the system files the released ones?** Witness measures every file and symlink on the system
   partition (256 on the demo image) into PCR 8 right after it is mounted, before anything on it runs,
   and the applications into PCR 9 before launch. The verifier predicts all of them from the build
   output.
3. **If not, what changed?** The verifier replays the event log and names the file:
   `CHANGED PCR 8 /system/etc/ssh/sshd_config`.

Each device also holds a **device key**, created inside its TPM, that the TPM lets it use only when PCR
0, 2, 4, 5, 7, 8 and 9 (firmware, boot image, disk, system partition, applications) equal the released
state. The key signs every attestation request, and the verifier checks that its TPM policy is
exactly the released state, computed from the build, so a tampered device loses its own credential
and cannot fake having it. A QNX security policy confines the TPM: even `root` logged in over ssh
cannot open `/dev/tpm0` or `/dev/tpmrm0`, so it cannot extend PCRs or use either key.

Everything below runs on QNX 8.0 under QEMU (x86_64, UEFI) with a software TPM (swtpm) attached
through the standard TPM TIS interface, the same register interface a discrete TPM chip exposes.

```
 QEMU x86_64 (OVMF UEFI) ── TIS MMIO 0xFED40000, IRQ 5 ── swtpm (TPM 2.0)
 │
 ├─ OVMF measures BOOTx64.EFI (= QNX IFS) ............................ PCR 4
 ├─ IFS script: dev-tpm-tis  → /dev/tpm0, /dev/tpm0-stats   (resource manager, type tpm_driver_t)
 ├─ startup.sh: witness-measure → system partition, after mount ...... PCR 8
 ├─ post_start: tabrm (QNX TCG resource manager) → /dev/tpmrm0
 │              over libtss2-tcti-witness → /dev/tpm0
 ├─ witness-measure → applications, before launch .................... PCR 9
 └─ witnessd (tss2 ESYS): AK, quote PCR 0-9, PCR-bound device key, TCP 7650
                                  │
 host: witness verify ────────────┘  signature, nonce, PCRs, event-log replay, per-file findings
```

## Build and run

| | Tested with |
|---|---|
| QNX | QNX Software Development Platform 8.0 (QNX Everywhere non-commercial licence), `qcc` / `gcc_ntox86_64` 12.2, `mkqnximage` |
| Target | QEMU `qemu-system-x86_64` 10.2.1, OVMF 2025.11 UEFI, swtpm 0.10.1 (TPM 2.0, TIS); KVM optional |
| Host | Linux x86_64 (Ubuntu under WSL2), Python 3.10+ with `uv` for the verifier |

```bash
source ~/qnx800/qnxsdp-env.sh            # QNX SDP 8.0 environment
cd witness                               # this repository
demo/demo.sh build      # cross-build for QNX 8.0, create the UEFI image with the Witness layer, compute reference values
demo/demo.sh up         # boot it headless with swtpm on the TIS interface
demo/demo.sh enroll     # record the attestation key and firmware baseline (known-good boot)
demo/demo.sh verify     # challenge the device and appraise its boot
demo/demo.sh attack     # as root on the device, try to use the TPM directly
demo/demo.sh tamper config && demo/demo.sh verify    # attacker edits sshd_config, reboots
demo/demo.sh restore && demo/demo.sh verify
demo/demo.sh down
```

`build` needs only the SDP; `up` needs `qemu-system-x86_64`, `swtpm` and OVMF
(`OVMF_CODE=/path/OVMF_CODE_4M.fd` if not in `/usr/share/OVMF`). SSH to the target:
`ssh -i .work/id_ed25519 -p 10022 root@127.0.0.1`. Host tests: `cd host && uv run --group dev pytest`.

### What you should see

```
127.0.0.1:10023  TRUSTED   device key: released (proven by TPM signature)
  pass  attestation key              AK 59a38e285aa23b6e
  pass  quote signature              ECDSA P-256 over TPMS_ATTEST
  pass  freshness                    quote carries this request's nonce
  pass  PCR values                   PCR 0-9 match the signed digest
  pass  boot disk layout (PCR 5)     GPT partition table is the released disk image's
  pass  firmware (PCR 0,1,2,3,6,7)   same firmware and configuration as at enrollment
  pass  boot image (PCR 4)           IFS is the released ifs.bin (Authenticode, measured by UEFI firmware)
  pass  event log (PCR 8)            log replays to the quoted PCR
  pass  event log (PCR 9)            log replays to the quoted PCR
  pass  system partition (PCR 8)     256 measurement(s) match the release
  pass  applications (PCR 9)         1 measurement(s) match the release
  pass  device key (PCR 0,2,4,5,7,8,9) TPM released the key bound to the released boot state; it signed our nonce
```

`demo.sh attack` (root shell on the device, secure policy):

```
# tpm-raw 8002000000410000018200000008...      (TPM2_PCR_Extend PCR 8)
tpm-raw: open /dev/tpm0: Operation not permitted
# env TPM_DEVICE=/dev/tpmrm0 tpm-raw 80010000000c0000017b0008
tpm-raw: open /dev/tpmrm0: Operation not permitted
# on -T witness_measure_t /proc/boot/witness-measure -p 8 -s forged
on: Operation not permitted (/proc/boot/witness-measure)
```

After `tamper config` and a reboot:

```
127.0.0.1:10023  NOT TRUSTED   device key: locked (reported by agent)
  FAIL  system partition (PCR 8)     1 difference(s) from the release
  FAIL  device key (PCR 0,2,4,5,7,8,9) TPM refused to release the device key: tpm:session(1):a policy check failed
       CHANGED  PCR 8  /system/etc/ssh/sshd_config
                  expected 4e2e95dc5d0f3652…  got 294c7dd0399bfc3a…
```

After `tamper lib` (a modified `libtss2-rc.so.1`, loaded by `witnessd` and `tabrm`):
`CHANGED PCR 8 /system/lib/libtss2-rc.so.1`, device key locked. After `tamper app` (the attestation
agent binary replaced): `/system/bin/witnessd` changed in PCR 8 and in PCR 9.

### Fleet dashboard

```bash
cd host
uv run witness dashboard -r ../.work/reference.json --state ../.work/state --device ecu-01=127.0.0.1:10023
uv run witness dashboard --replay tests/fixtures     # no QNX or TPM needed: captured evidence, verified offline
```

Open http://127.0.0.1:8650/. Each device is re-verified every 10 s; the detail page shows the trust
chain in boot order (firmware, boot image, disk, system partition, applications), the file that
changed with expected and measured digests, the replayed event log and PCR 0-9.

## Evidence of QNX use

All target code is C11 built with `qcc -Vgcc_ntox86_64` for QNX 8.0 ([Makefile](Makefile), `-Werror`,
stack protector, `_FORTIFY_SOURCE`; `make ARCH=aarch64le` builds for ARM too).

The QNX Driver Development Kit has frameworks for serial, I2C, SPI, HID, touch, network and CAN
devices, none for TPMs; for other devices its guide says to "follow the _Writing a Resource Manager_
documentation to create your own resource manager". `dev-tpm-tis` is that resource manager, for the
TPM TIS register interface.

| Component | File | QNX 8.0 facilities used |
|---|---|---|
| TPM TIS driver | [driver/tis.c](driver/tis.c) `tis_open`, `wait_sts`, `tis_transmit` | `mmap_device_memory` (TIS registers at 0xFED40000, `PROT_NOCACHE`); `InterruptAttachThread` + `InterruptWait` with `_NTO_INTR_WAIT_FLAGS_UNMASK`, bounded by `TimerTimeout(_NTO_TIMEOUT_INTR)`; polling fallback if the interrupt self-test gets no wake-up |
| Resource manager | [driver/main.c](driver/main.c) `io_write`, `io_read`, `io_notify`, `io_read_stats`, `main` | `dispatch_create`, two `resmgr_attach` paths (`/dev/tpm0`, `/dev/tpm0-stats`), custom OCB (`IOFUNC_OCB_T`, `iofunc_mount_t` ocb calloc/free) holding each client's response, `iofunc_notify` for `select`/`poll`, `procmgr_daemon` |
| TSS2 TCTI | [tcti/tcti-witness.c](tcti/tcti-witness.c) `Tss2_Tcti_Witness_Init`, `Tss2_Tcti_Info` | standard TCTI v2 module that the QNX TCG resource manager `tabrm` loads from its config ([image/tabrm.cfg](image/tabrm.cfg)) |
| Measurement | [tools/witness-measure.c](tools/witness-measure.c) `pcr_extend`, `measure_tree`, `measure_manifest` | runs from the IFS (`/proc/boot`), walks `/system` in sorted order (files by content, symlinks by target), raw `TPM2_PCR_Extend` through `/dev/tpm0`, event log in `/dev/shmem` |
| Attestation agent | [agent/witnessd.c](agent/witnessd.c) `create_attestation_key`, `create_device_key`, `device_key_sign`, `answer` | QNX TCG stack from the SDP (`libtss2-esys`, `-mu`, `-rc`, `-tctildr` → `libtcti_tabrm` → `/dev/tpmrm0`); `TPM2_Quote`; device key: `Create` with a `PolicyPCR` authPolicy, `Load`, `Sign` in a policy session |
| Boot customisation | [image/witness-image.sh](image/witness-image.sh) | `mkqnximage` snippets: driver started in the IFS script before the system partition is mounted; measurement in `startup_postfs`; `tabrm` and `witnessd` in `post_start`; IFS load address for current OVMF ([image/uefi/definitions.zz_witness](image/uefi/definitions.zz_witness)) |
| Security policy | [image/witness.secpol](image/witness.secpol) | QNX secpol: every Witness process starts under its own type (`START_P(tpm_driver_t)` …); only `tabrm_t` and `witness_measure_t` may connect to the driver and only `witnessd_t` to `tabrm`; the driver gets exactly `mem_phys` for its 4 KiB register page and `interrupt:5`. Built with `mkqnximage --secpol=secure --policy=…` |
| QEMU target | [scripts/vm.sh](scripts/vm.sh) | OVMF + `tpm-tis` device + swtpm, KVM when available |
| Verifier | [host/witness/](host/witness/) | reads `mkqnximage` build output (`ifs.build`, `system.build`, `ifs.bin`, `disk-qemu`) to predict PCR 4, 5, 8, 9 |

`/dev/tpm0-stats` reports the driver mode, command count, interrupt wake-ups and latency. Under the
secure policy a root login cannot read it either (same channel as `/dev/tpm0`); build with
`SECPOL=no demo/demo.sh build` (fresh `.work`) to inspect it. On an unconfined boot it showed 40 TPM
commands and 40 interrupt wake-ups (interrupt mode, IRQ 5).

## How the verifier decides

- **Attestation key**: ECC P-256 restricted signing key derived from the TPM endorsement hierarchy
  (deterministic, so the same TPM always gives the same key); trusted on first use at `enroll`.
- **Quote**: ECDSA signature over `TPMS_ATTEST`; the nonce in `extraData`; the quote must cover PCR
  0-9 and the reported PCR values must hash to its digest.
- **Firmware** (PCR 0,1,2,3,6,7): must equal the enrolled values.
- **Boot image** (PCR 4) and **disk layout** (PCR 5): predicted from the build output alone: the
  Authenticode digest of `ifs.bin` and the EDK2 GPT event of `disk-qemu`.
- **System partition and applications** (PCR 8, 9): the event log must replay to the quoted PCR, and
  every event must match the digest of the file in the build. Differences are named per file
  (changed, missing, unexpected, not measured).
- **Device key**: its signature over `"witness:device-key:" || nonce` must verify, it must be the
  enrolled key, and its `authPolicy` must equal `TPM2_PolicyPCR` over the released PCR 4, 5, 8, 9
  (from the build) and enrolled PCR 0, 2, 7, with `userWithAuth` clear. A key re-created on a
  tampered boot is therefore rejected.
- **Unenrolled devices** are NOT TRUSTED; only `witness enroll` accepts a new attestation key.

## Limits

- The TPM is swtpm, a software TPM, attached through the standard TIS interface. The driver is written
  against the TIS specification and the register interface a discrete TPM exposes; it has not run on
  physical TPM hardware.
- Timings measured under QEMU (KVM) are not hardware timings.
- The attestation key is trusted on first use; binding it to the TPM manufacturer's endorsement
  certificate is the production step, and swtpm has no manufacturer certificate.
- PCR 8 covers the read-mostly system partition (`/system`); the writable data partition (`/data`,
  e.g. `authorized_keys`, logs) is not measured. The policy in [image/witness.secpol](image/witness.secpol) was learned
  with `secpolgenerate` for this QEMU image and then tightened by hand for the TPM paths.

## AI tools used

Claude Code (Anthropic) wrote most of the code, scripts and documentation under the author's
direction; every result shown above was produced by running it on QNX 8.0 under QEMU.

## Licence

Apache-2.0, see [LICENSE](LICENSE).
