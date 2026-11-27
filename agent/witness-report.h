/* SPDX-License-Identifier: Apache-2.0 */
/* Signed fleet reports: the QNX message an application sends to witnessd's local channel, and the reply.
 * witnessd answers with the device key's signature over SHA256(REPORT_LABEL || report). The TPM releases the
 * device key only in a released boot state, so a fleet service that accepts reports only with a valid
 * signature cuts off a tampered or rolled-back device by itself. Who may connect is set by the security
 * policy (channel_connect:witnessd_t), not by witnessd. */
#ifndef WITNESS_REPORT_H
#define WITNESS_REPORT_H
#include <stdint.h>
#include <sys/iomsg.h>

#define REPORT_CHANNEL "witness/report" /* name_attach(): /dev/name/local/witness/report */
#define REPORT_LABEL "witness:report:"
#define REPORT_MSG (_IO_MAX + 0x57) /* above the _IO_* range */
#define REPORT_MAX 960               /* label + report fit one TPM2_Hash buffer (1024 bytes) */

struct report_request {
    uint16_t type; /* REPORT_MSG */
    uint16_t size; /* bytes used in report */
    char report[REPORT_MAX];
};

struct report_reply {
    uint32_t rc;   /* 0, or the TSS2 return code: the TPM refused (key locked) or another TPM error */
    uint16_t r_size, s_size;
    uint8_t r[32], s[32]; /* ECDSA P-256 signature */
};
#endif
