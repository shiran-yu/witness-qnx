/* SPDX-License-Identifier: Apache-2.0 */
/* TPM 2.0 TIS/FIFO interface (TCG PC Client Platform TPM Profile, FIFO interface) over MMIO. */
#ifndef WITNESS_TIS_H
#define WITNESS_TIS_H

#include <stddef.h>
#include <stdint.h>

#define TIS_DEFAULT_BASE 0xFED40000ULL /* locality 0 on PC platforms (and QEMU tpm-tis) */
#define TIS_LOCALITY_SPAN 0x1000
#define TIS_MAP_SIZE (5 * TIS_LOCALITY_SPAN)
#define TPM_BUFSIZE 4096 /* largest command/response we accept */

/* register offsets, relative to a locality's base */
#define TIS_ACCESS 0x00
#define TIS_INT_ENABLE 0x08
#define TIS_INT_VECTOR 0x0C
#define TIS_INT_STATUS 0x10
#define TIS_INTF_CAPS 0x14
#define TIS_STS 0x18
#define TIS_DATA_FIFO 0x24
#define TIS_INTERFACE_ID 0x30
#define TIS_DID_VID 0xF00
#define TIS_RID 0xF04

/* TPM_ACCESS bits */
#define ACCESS_VALID 0x80
#define ACCESS_ACTIVE_LOCALITY 0x20
#define ACCESS_REQUEST_PENDING 0x04
#define ACCESS_REQUEST_USE 0x02

/* TPM_STS bits */
#define STS_FAMILY_MASK 0x0C000000u /* 01 = TPM 2.0 */
#define STS_FAMILY_TPM2 0x04000000u
#define STS_VALID 0x80
#define STS_COMMAND_READY 0x40
#define STS_GO 0x20
#define STS_DATA_AVAIL 0x10
#define STS_EXPECT 0x08
#define STS_RESPONSE_RETRY 0x02

/* TPM_INT_ENABLE / TPM_INT_STATUS bits */
#define INT_GLOBAL_ENABLE 0x80000000u
#define INT_COMMAND_READY 0x80
#define INT_LOCALITY_CHANGE 0x04
#define INT_STS_VALID 0x02
#define INT_DATA_AVAIL 0x01

struct tis_stats {
    uint64_t commands;
    uint64_t errors;
    uint64_t irq_wakeups;
    uint64_t last_ns;  /* duration of the last transaction */
    uint64_t max_ns;   /* worst transaction since start */
};

struct tis {
    volatile uint8_t *base; /* mapped locality 0 */
    uint64_t paddr;
    int irq;                /* -1: polling */
    int irq_id;
    uint32_t did_vid;
    uint8_t rid;
    unsigned timeout_a_ms, timeout_b_ms, timeout_c_ms, timeout_long_ms;
    struct tis_stats stats;
    int verbose;
};

/* Map the registers and check a TPM 2.0 is present. Returns 0 or -errno. */
int tis_open(struct tis *t, uint64_t paddr, int irq, int verbose);
void tis_close(struct tis *t);

/* One full command/response transaction. cmd must be a complete TPM2 command.
 * Returns the response length (>= 10) or -errno. Not thread-safe: callers serialise. */
long tis_transmit(struct tis *t, const uint8_t *cmd, size_t len, uint8_t *resp, size_t max);

/* Abort the current command (sets commandReady); used after a timeout. */
void tis_cancel(struct tis *t);

#endif
