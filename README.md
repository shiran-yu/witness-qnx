# Witness: measured boot and remote attestation for QNX 8.0

> **For** operators and manufacturers of QNX devices in the field (vehicle gateways, robot controllers,
> medical and industrial devices) who must show that each device runs the software they released.
> **Try it without QNX:** `cd host && uv run witness dashboard --replay tests/fixtures/fleet` (the fleet
> below, from captured TPM evidence, verified offline). **On QNX 8.0 + QEMU:** `demo/demo.sh build up enroll verify`
> ([Build and run](#build-and-run)). **Where to look:** category Low-level Software, a TPM driver as a QNX
> resource manager ([Evidence of QNX use](#evidence-of-qnx-use)) · QNX-specific technologies, one row per
> technology ([QNX-specific technologies](#qnx-specific-technologies)) · codelab
> ([docs/codelab](docs/codelab/qnx-tpm-measured-boot-qemu.md)).

![Fleet dashboard: three QNX 8.0 devices on QEMU, each with its own TPM. gateway-a is trusted and its
device key is released; gateway-b was rolled back to release 1 and gateway-c runs a changed TPM library,
so the verifier names the file and both devices' keys stay locked.](docs/img/fleet-dashboard.png)

A fleet operator cannot see what a QNX device in the field actually booted. A changed binary or a
changed config file on a gateway, a robot controller or an infusion pump looks the same from the
outside until it misbehaves.

Witness gives a QNX 8.0 target a TPM 2.0 root of trust and lets a remote verifier answer, with a
signature from the TPM, three questions:

1. **Is this the image we released?** UEFI firmware measures the QNX IFS (boot image) into PCR 4.
2. **Are the system files the released ones?** Witness measures every file and symlink on the system
   partition and in `/etc` (`/data/var/etc`, the boot configuration; 253 on the demo image) into PCR 8
   right after they are mounted, before any boot script reads them, and the applications into PCR 9
   before launch. The verifier predicts all of them from the build
   output.
3. **If not, what changed?** The verifier replays the event log and names the file:
   `CHANGED PCR 8 /system/etc/ssh/sshd_config`.

Each device also holds a **device key**, created inside its TPM, that the TPM lets it use only when the
boot state (PCR 4, 5, 8 and 9: boot image, disk, system partition and `/etc`, applications) equals a
release signed by the build host's **release key** (`TPM2_PolicyAuthorize`), and the firmware
(PCR 0, 2, 7) equals this device's own. The key signs every attestation request, and the verifier
checks its TPM policy, so a tampered device loses its own credential and cannot fake having it. The
credential does a job: the device's heartbeat reports (`witness-report`: device, uptime, sequence number; every 10 s, bound to a one-time
challenge) reach the fleet service only signed by that key, through a QNX channel that only the report
app's security type may open, and the fleet service accepts nothing else. A tampered device is cut off
from its fleet backend by its own TPM, with no operator action. A
signed update keeps it: `demo.sh update` installs release v2 the way an update agent would (here over
ssh) and the same key is released again, with no re-provisioning. A rollback does not: each
release is numbered, and once the TPM has accepted release 2 it refuses release 1's genuine
signature (`TPM2_PolicyNV` over a set-only NV bit field). A QNX security policy confines the TPM: once the device has booted, even
`root` logged in over ssh cannot open `/dev/tpm0` or take the agent's type, so it cannot extend PCRs
or use either key. The boot script itself can (it starts those components), so Witness replaces
the stock mount step: nothing on `/system`, in `/etc` or on the EFI partition runs before it is
measured, and the stock `/boot/onboot` hook is not run at all.

Everything below runs on QNX 8.0 under QEMU (x86_64, UEFI) with a software TPM (swtpm) attached
through the standard TPM TIS interface, the same register interface a discrete TPM chip exposes.

```
 QEMU x86_64 (OVMF UEFI) ── TIS MMIO 0xFED40000, IRQ 5 ── swtpm (TPM 2.0)
 │
 ├─ OVMF measures BOOTx64.EFI (= QNX IFS) ............................ PCR 4
 ├─ IFS script: dev-tpm-tis  → /dev/tpm0, /dev/tpm0-stats   (resource manager, type tpm_driver_t)
 ├─ startup.sh: witness-measure → /system and /etc, after mount ...... PCR 8
 ├─ post_start: witness-measure → applications, before launch ........ PCR 9
 └─ witnessd (QNX tss2 ESYS → linked-in Witness TCTI → /dev/tpm0), supervised:
        AK, quote PCR 0-9, PCR-bound device key certified by the AK, TCP 7650
                                  │
 host: witness verify ────────────┘  signature, nonce, PCRs, event-log replay, per-file findings
```

## Why this matters

QNX runs in more than 275 million vehicles ([QNX, 16 Dec 2025](https://www.newswire.com/news/qnx-embedded-technology-now-powering-more-than-275-million-vehicles-on-the-road))
and in medical devices, industrial controls and robots. In each of these markets, regulation now
asks the manufacturer to know and prove what software a device in the field is running:

| Market | Requirement | In force |
|---|---|---|
| Vehicles (EU, UNECE) | UN R156: the manufacturer "can verify that the software version(s) present on a component of a type approved system are consistent with those defined by the relevant RXSWIN" (7.1.1.4); UN R155: "detect and prevent cyber-attacks" and "provide data forensic capability" (7.3.7) | R155 all new EU vehicles since 7 Jul 2024; R156 all new vehicles from 7 Jul 2026 ([EU 2019/2144](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02019R2144-20240707), [EU 2022/2236](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32022R2236), [R156 text](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:42021X0388)) |
| Any product with digital elements sold in the EU | Cyber Resilience Act, Annex I (2)(f): "protect the integrity of stored ... programs and configuration against any manipulation or modification ... and report on corruptions"; fines up to EUR 15 million or 2.5 % of turnover (Art. 64) | reporting from 11 Sep 2026, all obligations from 11 Dec 2027 ([Regulation (EU) 2024/2847](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202402847)) |
| Medical devices (US) | FD&C Act §524B for cyber devices; FDA guidance: "Ensure that the authenticity of software, firmware, and configuration are validated prior to execution", "Hardware-based security solutions should be considered", anti-replay "with the use of cryptographic nonces" | since 29 Mar 2023; guidance of 3 Feb 2026 ([FDA](https://www.fda.gov/media/119933/download)) |
| Industrial automation | IEC 62443-4-2 CR 3.14, integrity of the boot process: verify "the integrity of the firmware, software, and configuration data needed for the component's boot and runtime processes prior to use" (wording as given by [ISASecure](https://isasecure.org/hubfs/Webinars/Webinars%20PDFs/2019-August-8-Webinar.pdf)) | certification requirement |

The failures are real, and growing. Upstream Security analysed 494 publicly reported automotive and
smart-mobility incidents from 2025: "92% of automotive cyber attacks were conducted remotely", and
"61% of incidents had the potential to impact thousands to millions of mobility assets; 20% were
massive-scale events" ([Upstream, 18 Feb 2026](https://www.prnewswire.com/il/news-releases/ransomware-attacks-on-automotive-and-smart-mobility-more-than-doubled-in-2025-according-to-new-research-by-upstream-security-302691468.html)).
A remote attacker at fleet scale is exactly the case where an operator must ask each device to prove
its state instead of assuming it. A backdoor in the Contec CMS8000 patient monitor allowed "device modification"
([CISA, Feb 2025](https://www.cisa.gov/resources-tools/resources/contec-cms8000-contains-backdoor));
attackers compromised at least 75 Unitronics PLCs, 34 of them in US water and wastewater systems
([CISA AA23-335A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a)).

Witness maps onto these requirements directly: the release defines the expected measurement of every
file (the role of RXSWIN integrity data), the device proves its boot state with a TPM signature over
a fresh nonce, a change is reported by file name, and a device that is not in the released state
loses the key it would use to talk to its fleet service. Software updates are part of the same
chain: a release signed on the build host keeps the device's key, and once it has run, the TPM
itself refuses the older signed release, so "the version defined by the RXSWIN" cannot be swapped
for a vulnerable earlier one.

**Why QNX is the right foundation.** Attestation must not cost a control loop its deadline, and it
must not become a new way into the device. QNX's architecture gives both, and Witness uses it:

- *Isolation by process, not by trust.* The TPM driver, the measurement tool and the agent are
  separate user-space processes behind QNX message passing. A fault in the network-facing agent does
  not reach the driver or the kernel, and a supervisor restarts the agent if its TPM work for one
  request outlives a 10 s watchdog. Network clients cannot trigger that: up to 64 are read at once,
  each must send its request within 2 s, and the watchdog starts only after the request is in.
- *Least privilege enforced by the kernel.* The QNX security policy gives each process only what it
  needs: the driver gets its one 4 KiB register page and its interrupt; after boot only the
  measurement tool and the agent may reach the driver (the boot script, which starts them, can too);
  a root login gets neither the driver nor their types.
- *Priority-ordered service.* A QNX server receives messages in priority order and runs at its
  client's priority. witnessd runs at priority 8, below QNX's default 10, so the TPM driver serves
  attestation at 8 too, and the scheduler does not let it preempt work at QNX's default priority or above. Measured under QEMU
  ([demo/latency.sh](demo/latency.sh), [docs/evidence/latency.log](docs/evidence/latency.log)): a
  1 kHz loop at priority 10 while the host floods witnessd (~22 attestations/s) had 0, 1 and 2
  periods over 1 ms late in three 30 s runs, as many as idle (2, 38, 1); the same loop at priority 7,
  below witnessd, had 8, 5 and 6108. QEMU on a laptop, not hardware timings: the rows compare.
- *Measure before use.* The driver and the measurement tool live in the boot image, which the
  firmware measures, and run from QNX's own boot script before it reads anything on the system
  partition or in `/etc` (where `start_net.sh` sources `settings/network` as shell code). The stock
  `mount_fs.sh` would run `/boot/onboot` and `/system/bin/cleanup_tmp` first, so Witness skips it,
  mounts the partitions itself, measures, and only then runs `cleanup_tmp`; `/boot` is mounted
  read-only.

## Build and run

| | Tested with |
|---|---|
| QNX | QNX Software Development Platform 8.0 (QNX Everywhere non-commercial licence), `qcc` / `gcc_ntox86_64` 12.2, `mkqnximage` |
| Target | QEMU `qemu-system-x86_64` 10.2.1, OVMF 2025.11 UEFI, swtpm 0.10.1 (TPM 2.0, TIS); KVM optional |
| Host | Linux x86_64 (Ubuntu under WSL2), Python 3.10+ with `uv` for the verifier |

```bash
source ~/qnx800/qnxsdp-env.sh            # QNX SDP 8.0 environment
git clone https://github.com/shiran-yu/witness-qnx witness && cd witness
demo/demo.sh build      # cross-build for QNX 8.0, create the UEFI image with the Witness layer, compute reference values
demo/demo.sh up         # boot it headless with swtpm on the TIS interface
demo/demo.sh enroll     # record the attestation key and firmware baseline (known-good boot)
demo/demo.sh verify     # challenge the device and appraise its boot
demo/demo.sh attack     # as root on the device, try to use the TPM directly
demo/demo.sh tamper config && demo/demo.sh verify    # attacker edits sshd_config, reboots
demo/demo.sh restore && demo/demo.sh verify
demo/demo.sh update && demo/demo.sh verify     # signed release v2 installed; same device key
demo/demo.sh rollback && demo/demo.sh verify   # signed v1 reinstalled: the TPM refuses the key (anti-rollback)
demo/demo.sh down
```

`build` needs only the SDP; `up` needs `qemu-system-x86_64`, `swtpm` and OVMF
(`OVMF_CODE=/path/OVMF_CODE_4M.fd` if not in `/usr/share/OVMF`). SSH to the target:
`ssh -i .work/id_ed25519 -p 10022 root@127.0.0.1`. Host tests: `cd host && uv run --group dev pytest`.

### What you should see

(254 measurements: 253 files and symlinks plus the end-of-measurement marker; PCR 9: witnessd and
witness-report.) A complete recorded run (build, boot, enroll, attack, four tampers, restores, a signed
update, a rollback) is in [docs/evidence/golden-path.log](docs/evidence/golden-path.log), with the QNX
boot console in [docs/evidence/qnx-console-last-boot.log](docs/evidence/qnx-console-last-boot.log); the
signed fleet reports accepted, then rejected after a tamper, then accepted after the restore are in
[docs/evidence/fleet-reports.log](docs/evidence/fleet-reports.log). These runs used QEMU without KVM
(`accel: -cpu max` in the log), so boot times there are emulation times.

```
127.0.0.1:10023  TRUSTED   device key: released (proven by TPM signature)
  pass  attestation key              AK 440853652aaf657f
  pass  quote signature              ECDSA P-256 over TPMS_ATTEST
  pass  freshness                    quote carries this request's nonce
  pass  PCR values                   PCR 0-9 match the signed digest
  pass  boot disk layout (PCR 5)     GPT partition table is the released disk image's
  pass  firmware (PCR 0,1,2,3,6,7)   same firmware and configuration as at enrollment
  pass  boot image (PCR 4)           IFS is the released ifs.bin (Authenticode, measured by UEFI firmware)
  pass  event log (PCR 8)            log replays to the quoted PCR
  pass  event log (PCR 9)            log replays to the quoted PCR
  pass  system and /etc (PCR 8)      254 measurement(s) match the release
  pass  applications (PCR 9)         2 measurement(s) match the release
  pass  device key (signed release + PCR 0,2,7) TPM released the key bound to the released boot state; it signed our nonce
```

`demo.sh attack` (root shell on the device, secure policy):

```
# tpm-raw 8002000000410000018200000008...      (TPM2_PCR_Extend PCR 8)
tpm-raw: open /dev/tpm0: Operation not permitted
# on -T witnessd_t /system/bin/witnessd -f -p 7651     (a second agent to use the device key)
on: Operation not permitted (/system/bin/witnessd)
# on -T witness_measure_t /proc/boot/witness-measure -p 8 -s forged
on: Operation not permitted (/proc/boot/witness-measure)
# witness-report -c                                    (open the agent's channel that signs fleet reports)
witness-report: no channel to witnessd: Operation not permitted
# echo touch /tmp/pwned > /boot/onboot                 (a boot hook; it would not be run anyway)
sh: cannot create /boot/onboot: Read-only file system
# swap /system/lib/libtss2-esys.so.1, then kill the agent so its supervisor restarts it
  no effect: restarted agent 1003542 is a fork of supervisor 454676 (no exec), mapping the same 11 objects it loaded at the measured launch
```

Root can write `/system` and signal the agent, so the last check matters: the supervisor restarts the agent
with `fork`, never `exec`, and the agent loads no library after its measured launch (the TCTI is linked
into `witnessd`, OpenSSL is initialised before the first fork), so a swapped library (here one the agent
maps) cannot run under the agent's type until a reboot measures it.
Killing the supervisor stops attestation (denial of service; the verifier then reports the device
unreachable, not trusted).

After `tamper config` and a reboot:

```
127.0.0.1:10023  NOT TRUSTED   device key: locked (agent’s claim, not verified)
  FAIL  system and /etc (PCR 8)      1 difference(s) from the release
  FAIL  device key (signed release + PCR 0,2,7) TPM refused to release the device key: tpm:parameter(1):value is out of range or is not correct for the context
       CHANGED  PCR 8  /system/etc/ssh/sshd_config
                  expected 4e2e95dc5d0f3652…  got 294c7dd0399bfc3a…
```

After `tamper lib` (a modified `libtss2-rc.so.1`, loaded by `witnessd`):
`CHANGED PCR 8 /system/lib/libtss2-rc.so.1`, device key locked. After `tamper app` (the attestation
agent binary replaced): `/system/bin/witnessd` changed in PCR 8 and in PCR 9. After `tamper data` (a
command appended to `/etc/settings/network`, which `start_net.sh` runs as root at boot):
`CHANGED PCR 8 /data/var/etc/settings/network`, device key locked. After `update` (release v2,
`sshd_config` with `MaxAuthTries 3`, signed on the build host and installed over ssh): TRUSTED
against the v2 reference, and the device key is released again, the same enrolled key. After
`rollback` (the v1 file and its genuine signed v1 policy reinstalled): `NOT TRUSTED`, `device key:
locked`, `FAIL device key (signed release + PCR 0,2,7) TPM refused to release the device key:
tpm:error(2.0): policy failure in math operation or an invalid authPolicy value`; the TPM's `PolicyNV`
check fails because v2 has run. Checked against v1's own reference, every measurement passes (11
of 12 checks) and only the device key fails: the boot is a genuine v1, and the TPM still refuses it.
`restore` reinstalls v2: TRUSTED again.

### Fleet dashboard

```bash
cd host
uv run witness dashboard -r ../.work/reference.json --state ../.work/state --device ecu-01=127.0.0.1:10023 \
    --environment "QNX 8.0 on QEMU, software TPM"
uv run witness dashboard --replay tests/fixtures/fleet   # no QNX or TPM needed: three captured devices, verified offline
uv run witness dashboard --replay tests/fixtures     # one trusted device and one with a changed config
uv run witness dashboard --replay tests/fixtures/release   # signed release v2: current device, and one rolled back to v1
```

Open http://127.0.0.1:8650/. Each device is re-verified every 10 s; the detail page shows the trust
chain in boot order (firmware, boot image, disk, system partition, applications), the file that
changed with expected and measured digests, the replayed event log and PCR 0-9.

A three-device fleet, each QEMU VM with its own swtpm (its own attestation key, device key and
anti-rollback bits), after `demo.sh build up enroll update`:

```bash
demo/fleet.sh up          # gateway-b, gateway-c: copies of gateway-a's disk with new TPMs, enrolled; then
                          # gateway-b rolls back to v1, gateway-c gets a modified TPM library
demo/fleet.sh dashboard   # gateway-a TRUSTED; gateway-b "sshd_config rolled back to release 1", key
                          # refused by its TPM; gateway-c "libtss2-rc.so.1 changed", key locked
```

Recorded run: [docs/evidence/fleet.log](docs/evidence/fleet.log) (gateway-b's TPM fails `PolicyNV`, a
policy failure; gateway-c's fails `PolicyPCR`, a value error). A copied disk does not copy the device: gateway-a's device key file cannot be loaded by another TPM,
so `fleet.sh` deletes it and each clone provisions its own key and is enrolled with its own
attestation key. A file that equals an older release's version is named as a rollback: `witness reference --previous`
records the files that differ from the previous release, and `demo.sh update` passes it.

## Evidence of QNX use

All target code is C11 built with `qcc -Vgcc_ntox86_64` for QNX 8.0 ([Makefile](Makefile), `-Werror`,
stack protector, `_FORTIFY_SOURCE`; `make ARCH=aarch64le` builds for ARM too).

The QNX Driver Development Kit has frameworks for serial, I2C, SPI, HID, touch, network and CAN
devices, none for TPMs; for other devices its guide says to "follow the _Writing a Resource Manager_
documentation to create your own resource manager". `dev-tpm-tis` is that resource manager, for the
TPM TIS register interface.

**Why a resource manager, not QNX's TPM driver base.** The SDP's `security.tcg.tpm.driver.base`
package ships `tcti_tpm_driver_base.so`, a TCTI that `dlopen`s a board vendor's hardware module
(`tpm_mod.so`, per `etc/sample_tcti_tpm_driver_base.cfg`); no hardware module comes with the SDP.
That design runs the hardware access inside every TPM client process, so each client would need the
TPM's physical memory and interrupt. As a resource manager, only `dev-tpm-tis` holds them; clients
reach it over a QNX channel that the security policy grants per type (only the measurement tool and
the agent), and the kernel serialises their commands in priority order. A `tpm_mod.so` built on the
same TIS code would let QNX's driver base use a TIS TPM too; we have not built one.

**QTD.** QNX Trusted Disk checks `/system` blocks against a signed hash tree as they are read, on the
device. Witness is the remote half: a verifier off the device learns what booted and can refuse it a
credential. Witness's mount step handles the qnx6 image this demo uses, not QTD or qcfs partitions.

| Component | File | QNX 8.0 facilities used |
|---|---|---|
| TPM TIS driver | [driver/tis.c](driver/tis.c) `tis_open`, `wait_sts`, `tis_transmit` | `mmap_device_memory` (TIS registers at 0xFED40000, `PROT_NOCACHE`); `InterruptAttachThread` + `InterruptWait` with `_NTO_INTR_WAIT_FLAGS_UNMASK`, bounded by `TimerTimeout(_NTO_TIMEOUT_INTR)`; polling fallback if the interrupt self-test gets no wake-up |
| Resource manager | [driver/main.c](driver/main.c) `io_write`, `io_read`, `io_notify`, `io_read_stats`, `main` | `dispatch_create`, two `resmgr_attach` paths (`/dev/tpm0`, `/dev/tpm0-stats`), custom OCB (`IOFUNC_OCB_T`, `iofunc_mount_t` ocb calloc/free) holding each client's response, `iofunc_notify` for `select`/`poll`, `procmgr_daemon` |
| TSS2 TCTI | [tcti/tcti-witness.c](tcti/tcti-witness.c) `Tss2_Tcti_Witness_Init`, `Tss2_Tcti_Info` | standard TCTI v2 module: linked into `witnessd` (a restarted agent maps only what its supervisor loaded at launch; `demo.sh attack` checks it), and also built as `libtss2-tcti-witness.so.0` for any `libtss2-tctildr` client (`witness:/dev/tpm0`) |
| Measurement | [tools/witness-measure.c](tools/witness-measure.c) `pcr_extend`, `measure_tree`, `measure_manifest` | runs from the IFS (`/proc/boot`), walks `/system` in sorted order (files by content, symlinks by target), raw `TPM2_PCR_Extend` through `/dev/tpm0`, event log in `/dev/shmem` |
| Attestation agent | [agent/witnessd.c](agent/witnessd.c) `create_attestation_key`, `create_device_key`, `device_key_sign`, `policy_release_number`, `record_release_number`, `answer`, `flush_stale_handles`, `main` (supervisor) | QNX TCG stack from the SDP (`libtss2-esys`, `-mu`, `-rc`) over the linked-in TCTI; `TPM2_Quote`; device key: `Create` with a `PolicyAuthorize` (release key) + `PolicyPCR` (PCR 0, 2, 7) authPolicy, `Load`, `Sign` in a policy session (`PolicyPCR` → `LoadExternal` + `VerifySignature` of the signed release policy → `PolicyAuthorize` → `PolicyPCR`), `Certify` by the AK; `fork` supervisor and `alarm` watchdog |
| Boot customisation | [image/witness-image.sh](image/witness-image.sh) | `mkqnximage` snippets: driver started in the IFS script before the system partition is mounted; measurement in `startup_postfs`; application measurement and `witnessd` in `post_start`; IFS load address for current OVMF ([image/uefi/definitions.zz_witness](image/uefi/definitions.zz_witness)) |
| Security policy | [image/witness.secpol](image/witness.secpol) | QNX secpol: every Witness process starts under its own type (`START_P(tpm_driver_t)` …); only `witness_measure_t` and `witnessd_t` may connect to the driver; the driver gets exactly `mem_phys` for its 4 KiB register page and `interrupt:5`. Built with `mkqnximage --secpol=secure --policy=…` |
| QEMU target | [scripts/vm.sh](scripts/vm.sh) | OVMF + `tpm-tis` device + swtpm, KVM when available |
| Verifier | [host/witness/](host/witness/) | reads `mkqnximage` build output (`ifs.build`, `system.build`, `ifs.bin`, `disk-qemu`) to predict PCR 4, 5, 8, 9 |

`/dev/tpm0-stats` reports the driver mode, command count, interrupt wake-ups and latency. Under the
secure policy a root login cannot read it either (same channel as `/dev/tpm0`); build with
`SECPOL=no demo/demo.sh build` (fresh `.work`) to inspect it. The boot console shows which mode the
driver chose (`interrupt driven` after its interrupt self-test, or polling):
[docs/evidence/qnx-console-last-boot.log](docs/evidence/qnx-console-last-boot.log).

## QNX-specific technologies

One row per capability the QNX platform offers and Witness depends on. Witness does not use adaptive
partitioning, pulses of its own, qvm or QTD.

| QNX capability | What Witness does with it | Evidence |
|---|---|---|
| Resource managers | The TPM driver is a resource manager serving `/dev/tpm0` and `/dev/tpm0-stats`: custom OCB per client, `iofunc_notify` for `select`/`poll` | [driver/main.c](driver/main.c) (`resmgr_attach`, `dispatch_create`) |
| Native message passing | Every TPM command from the measurement tool and the agent is a QNX message to that one process; the kernel queues the clients in priority order, so no client needs the TPM's memory or interrupt. witnessd's own channel (`name_attach`) signs fleet reports: `MsgSend` from the report app, `MsgReceive`/`MsgReply` in the agent, running at the sender's priority | [driver/main.c](driver/main.c) `io_write`/`io_read`; [tcti/tcti-witness.c](tcti/tcti-witness.c); [agent/witnessd.c](agent/witnessd.c) `report_channel`; [tools/witness-report.c](tools/witness-report.c) |
| Microkernel architecture | Hardware access lives in one user-space process with exactly one 4 KiB register page and one interrupt; the agent is a separate process under a supervisor that restarts it | [driver/tis.c](driver/tis.c) `mmap_device_memory`; [agent/witnessd.c](agent/witnessd.c) `main` |
| QNX 8.0 interrupt model | `InterruptAttachThread` + `InterruptWait`, bounded with `TimerTimeout(_NTO_TIMEOUT_INTR)`; an interrupt self-test falls back to polling | [driver/tis.c](driver/tis.c); boot console line `interrupt driven` |
| Startup and boot customisation | `mkqnximage` snippets start the driver in the IFS script and measure `/system` and `/etc` right after mount, before any boot script reads them; the IFS load address is moved so current OVMF loads it | [image/witness-image.sh](image/witness-image.sh), [image/uefi/definitions.zz_witness](image/uefi/definitions.zz_witness) |
| Security policies | Each component runs under its own secpol type; only the measurement tool and the agent may connect to the driver, and only the report app (`witness_report_t`) to the agent's signing channel; root over ssh gets "Operation not permitted" on both | [image/witness.secpol](image/witness.secpol); `demo.sh attack` |
| Real-time services | The agent runs at priority 8, below QNX's default 10; a 1 kHz `SCHED_FIFO` loop at 10 saw no more late periods during an attestation flood than idle (QEMU, three runs) | [agent/witnessd.c](agent/witnessd.c) `pthread_setschedparam`; [docs/evidence/latency.log](docs/evidence/latency.log) |
| QNX's TCG software stack | The agent uses the SDP's `libtss2-esys`/`-mu`/`-rc`; Witness adds the TCTI module the SDP does not ship | [tcti/tcti-witness.c](tcti/tcti-witness.c) |

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
  enrolled key, and its `authPolicy` must equal `TPM2_PolicyAuthorize` by the release key named in
  the reference followed by `TPM2_PolicyPCR` over the enrolled PCR 0, 2, 7; the release's signed
  policy (`TPM2_PolicyPCR` over PCR 4, 5, 8, 9, then `TPM2_PolicyNV`: no release newer than this
  one has run) must match both the reference and the quoted PCRs, so a device on an older signed
  release fails (images without a release key: `TPM2_PolicyPCR` over
  the released PCR 4, 5, 8, 9 and enrolled PCR 0, 2, 7), with `userWithAuth` clear, and a `TPM2_Certify` by the
  attestation key over the same nonce must name exactly this key, so it is a key inside this TPM. A
  key re-created on a tampered boot is therefore rejected.
- **Unenrolled devices** are NOT TRUSTED; only `witness enroll` accepts a new attestation key.

## Limits

- One reference describes one release, byte for byte, including `/etc`: every device checked against
  it must have the same passwords, hostname and network settings. A device with its own settings
  needs its own reference (or the per-device files moved out of `/etc`), and an admin change such as
  `passwd` makes the device NOT TRUSTED until it is re-released.
- The TPM is swtpm, a software TPM, attached through the standard TIS interface. The driver is written
  against the TIS specification and the register interface a discrete TPM exposes; it has not run on
  physical TPM hardware.
- Timings measured under QEMU (KVM) are not hardware timings.
- Enroll and verify under the same QEMU acceleration: with and without KVM the virtual CPU differs,
  which changes PCR 1, and the firmware check fails (`vm.sh` prints the `accel` it used).
- The attestation key is trusted on first use; binding it to the TPM manufacturer's endorsement
  certificate is the production step, and swtpm has no manufacturer certificate.
- Measurement happens at boot. A file changed while the device runs is reported after the next
  boot, not before (the demo reboots after each tamper for that reason). File contents and symlink
  targets are measured; owners, modes and setuid bits are not.
- PCR 8 covers the system partition (`/system`) and `/etc` (`/data/var/etc`). The rest of the
  writable data partition (`/data`, e.g. `authorized_keys`, ssh host keys, logs) is not measured;
  the stock boot script reads nothing else there as code.
- Anti-rollback: release N's signed policy requires bits N..63 of an NV bit field (index
  `0x01005700`) to be clear, and `witnessd` sets bits 0..N-1 once the TPM has accepted release N;
  bits can be set, never cleared. Every release must be numbered: `witness reference --release-key`
  refuses to sign without `--release-number`, and `witnessd` ignores an unnumbered policy (it would
  skip `PolicyNV`). In the demo, "v1" and "v2" are the two newest numbers: each `build` and `update`
  takes the next one (`.work/release-number`), because the swtpm state and its NV bits outlive
  rebuilds. Limits: 63 release numbers per TPM; the index is defined under the
  owner hierarchy with an empty owner password, so code with TPM access could undefine and recreate
  it (after boot the security policy denies TPM access to everything but the measurer and the
  agent; production sets an owner password or `TPMA_NV_POLICY_DELETE`); anyone with TPM access can
  set bits and so lock out releases (denial of service, not a bypass).
- Firmware updates: the device key is bound to this device's PCR 0, 2, 7, so a firmware or Secure
  Boot db/dbx update locks it for good. The device is then re-provisioned (delete
  `/data/var/witness/device-key.blob`, reboot) and re-enrolled (`witness enroll --force`); signed
  software releases need neither.
- An update release here is the released build plus replaced files (`witness reference --replace`);
  an update that changes the boot image (PCR 4) needs the EFI partition rewritten, which the demo's
  read-only `/boot` does not allow from a root shell.
- The policy in [image/witness.secpol](image/witness.secpol) was learned with `secpolgenerate` for
  this QEMU image and then tightened by hand for the TPM paths.
- witnessd talks to the TPM driver directly rather than through QNX's `tabrm` resource manager: in
  testing, `tabrm` twice left a client blocked forever, and after boot witnessd is the only TPM client.

## Codelab

[Measured boot on QNX 8.0: give your QEMU target a TPM](docs/codelab/qnx-tpm-measured-boot-qemu.md)
teaches the first link on its own: boot QNX 8.0 through UEFI with a software TPM, read PCR 4 from
QNX through `dev-tpm-tis`, and predict the same value on the host from `ifs.bin`.

## AI tools used

Claude Code (Anthropic) wrote most of the code, scripts and documentation under the author's
direction; every result shown above was produced by running it on QNX 8.0 under QEMU. The demo
video's narration is the author's own voice, synthesised with an AI voice model.

## Licence

Apache-2.0, see [LICENSE](LICENSE).
