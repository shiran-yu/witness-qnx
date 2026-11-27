/* SPDX-License-Identifier: Apache-2.0 */
/* TIS/FIFO transport. Follows the TCG PC Client Platform TPM Profile (PTP) FIFO flow:
 * request locality -> commandReady -> write FIFO in burstCount chunks -> tpmGo ->
 * wait dataAvail -> read FIFO -> commandReady -> release locality. */
#include "tis.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <time.h>

#define LOG(t, ...) do { if ((t)->verbose) fprintf(stderr, "dev-tpm-tis: " __VA_ARGS__); } while (0)

static inline uint8_t rd8(struct tis *t, unsigned off) { return t->base[off]; }
static inline void wr8(struct tis *t, unsigned off, uint8_t v) { t->base[off] = v; }
static inline uint32_t rd32(struct tis *t, unsigned off) { return *(volatile uint32_t *)(t->base + off); }
static inline void wr32(struct tis *t, unsigned off, uint32_t v) { *(volatile uint32_t *)(t->base + off) = v; }

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void pause_us(unsigned us)
{
    struct timespec ts = {0, (long)us * 1000};
    nanosleep(&ts, NULL);
}

/* Wait until (STS & mask) == mask. Returns 0 or -ETIMEDOUT.
 * irq_bits != 0: block on the interrupt (used only while the TPM executes a command, which takes ms);
 * irq_bits == 0: poll with backoff (register handshakes settle in microseconds and QEMU raises no
 * stsValid interrupt for them). */
static int wait_sts(struct tis *t, uint8_t mask, unsigned timeout_ms, uint32_t irq_bits)
{
    uint64_t deadline = now_ns() + (uint64_t)timeout_ms * 1000000ull;
    unsigned backoff = 10;

    for (;;) {
        uint8_t sts = rd8(t, TIS_STS);
        if ((sts & mask) == mask)
            return 0;
        uint64_t n = now_ns();
        if (n >= deadline)
            return -ETIMEDOUT;
        if (t->irq >= 0 && irq_bits) {
            /* Interrupt mode: block until the TPM raises its line; re-check at least every 10 ms
             * so a lost or misrouted interrupt costs latency, never a timeout. */
            uint64_t left = deadline - n;
            if (left > 10000000ull)
                left = 10000000ull;
            wr32(t, TIS_INT_ENABLE, INT_GLOBAL_ENABLE | irq_bits);
            sts = rd8(t, TIS_STS); /* re-check after enabling, the event may already be there */
            if ((sts & mask) != mask) {
                /* InterruptWait's own timeout argument must be NULL; QNX bounds kernel blocking with TimerTimeout */
                TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_INTR, NULL, &left, NULL);
                if (InterruptWait(_NTO_INTR_WAIT_FLAGS_UNMASK, NULL) == 0)
                    t->stats.irq_wakeups++;
                else if (t->verbose > 1)
                    LOG(t, "InterruptWait: %s (int_status 0x%x)\n", strerror(errno), rd32(t, TIS_INT_STATUS));
            }
            wr32(t, TIS_INT_STATUS, rd32(t, TIS_INT_STATUS)); /* write-1-to-clear */
            continue;
        }
        pause_us(backoff);
        if (backoff < 1000)
            backoff *= 2;
    }
}

static int request_locality(struct tis *t)
{
    if ((rd8(t, TIS_ACCESS) & (ACCESS_VALID | ACCESS_ACTIVE_LOCALITY)) == (ACCESS_VALID | ACCESS_ACTIVE_LOCALITY))
        return 0;
    wr8(t, TIS_ACCESS, ACCESS_REQUEST_USE);
    uint64_t deadline = now_ns() + (uint64_t)t->timeout_a_ms * 1000000ull;
    while (now_ns() < deadline) {
        uint8_t a = rd8(t, TIS_ACCESS);
        if ((a & (ACCESS_VALID | ACCESS_ACTIVE_LOCALITY)) == (ACCESS_VALID | ACCESS_ACTIVE_LOCALITY))
            return 0;
        pause_us(50);
    }
    return -ETIMEDOUT;
}

static void release_locality(struct tis *t)
{
    wr8(t, TIS_ACCESS, ACCESS_ACTIVE_LOCALITY); /* writing activeLocality relinquishes it */
}

static unsigned burst_count(struct tis *t)
{
    uint64_t deadline = now_ns() + 30ull * 1000000ull; /* TIMEOUT_D */
    do {
        unsigned b = rd8(t, TIS_STS + 1) | (unsigned)rd8(t, TIS_STS + 2) << 8;
        if (b)
            return b;
        pause_us(20);
    } while (now_ns() < deadline);
    return 0;
}

void tis_cancel(struct tis *t)
{
    wr8(t, TIS_STS, STS_COMMAND_READY);
}

int tis_open(struct tis *t, uint64_t paddr, int irq, int verbose)
{
    memset(t, 0, sizeof *t);
    t->paddr = paddr;
    t->irq = -1;
    t->verbose = verbose;
    /* TCG PTP default timeouts */
    t->timeout_a_ms = 750;
    t->timeout_b_ms = 2000;
    t->timeout_c_ms = 750;
    t->timeout_long_ms = 120000; /* key generation on slow TPMs */

    void *p = mmap_device_memory(NULL, TIS_LOCALITY_SPAN, PROT_READ | PROT_WRITE | PROT_NOCACHE, 0, paddr);
    if (p == MAP_FAILED)
        return -errno;
    t->base = p;

    uint8_t access = rd8(t, TIS_ACCESS);
    t->did_vid = rd32(t, TIS_DID_VID);
    if (access == 0xFF || !(access & ACCESS_VALID) || t->did_vid == 0xFFFFFFFFu || t->did_vid == 0) {
        LOG(t, "no TIS TPM at 0x%llx (access=0x%02x did_vid=0x%08x)\n", (unsigned long long)paddr, access, t->did_vid);
        tis_close(t);
        return -ENODEV;
    }
    t->rid = rd8(t, TIS_RID);

    int rc = request_locality(t);
    if (rc) {
        tis_close(t);
        return rc;
    }
    uint32_t sts = rd32(t, TIS_STS);
    if ((sts & STS_FAMILY_MASK) != STS_FAMILY_TPM2) {
        LOG(t, "TPM at 0x%llx is not TPM 2.0 (sts=0x%08x)\n", (unsigned long long)paddr, sts);
        release_locality(t);
        tis_close(t);
        return -ENOTSUP;
    }
    release_locality(t);

    if (irq >= 0) {
        /* QNX 8.0 interrupt model: this thread becomes the interrupt service thread. */
        wr32(t, TIS_INT_ENABLE, 0);
        wr32(t, TIS_INT_STATUS, 0xFFFFFFFFu);
        LOG(t, "intf_caps 0x%08x int_vector %u\n", rd32(t, TIS_INTF_CAPS), rd8(t, TIS_INT_VECTOR));
        int id = InterruptAttachThread(irq, _NTO_INTR_FLAGS_NO_UNMASK);
        if (id == -1) {
            LOG(t, "InterruptAttachThread(%d): %s; falling back to polling\n", irq, strerror(errno));
        } else {
            t->irq = irq;
            t->irq_id = id;
            /* Self-test: one TPM2_GetRandom must raise at least one interrupt, else the line is wrong. */
            static const uint8_t get_random[] = {0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7B, 0, 8};
            uint8_t response[64];
            long r = tis_transmit(t, get_random, sizeof get_random, response, sizeof response);
            if (r < 0 || t->stats.irq_wakeups == 0) {
                LOG(t, "no interrupt seen on line %d during self-test; falling back to polling\n", irq);
                wr32(t, TIS_INT_ENABLE, 0);
                InterruptDetach(id);
                t->irq = -1;
            }
            memset(&t->stats, 0, sizeof t->stats);
        }
    }
    LOG(t, "TPM 2.0 at 0x%llx vendor 0x%04x device 0x%04x rev %u, %s\n", (unsigned long long)paddr,
        t->did_vid & 0xFFFF, t->did_vid >> 16, t->rid, t->irq >= 0 ? "interrupt driven" : "polled");
    return 0;
}

void tis_close(struct tis *t)
{
    if (t->irq >= 0) {
        wr32(t, TIS_INT_ENABLE, 0);
        InterruptDetach(t->irq_id);
        t->irq = -1;
    }
    if (t->base)
        munmap_device_memory((void *)t->base, TIS_LOCALITY_SPAN);
    t->base = NULL;
}

static int send_command(struct tis *t, const uint8_t *cmd, size_t len)
{
    int rc;
    if (!(rd8(t, TIS_STS) & STS_COMMAND_READY)) {
        wr8(t, TIS_STS, STS_COMMAND_READY);
        if ((rc = wait_sts(t, STS_COMMAND_READY, t->timeout_b_ms, 0)))
            return rc;
    }
    size_t sent = 0;
    while (sent < len - 1) {
        unsigned burst = burst_count(t);
        if (!burst)
            return -EIO;
        while (burst-- && sent < len - 1)
            wr8(t, TIS_DATA_FIFO, cmd[sent++]);
        if ((rc = wait_sts(t, STS_VALID, t->timeout_c_ms, 0)))
            return rc;
        if (!(rd8(t, TIS_STS) & STS_EXPECT))
            return -EIO; /* TPM thinks the command ended early: length field mismatch */
    }
    wr8(t, TIS_DATA_FIFO, cmd[sent]); /* last byte */
    if ((rc = wait_sts(t, STS_VALID, t->timeout_c_ms, 0)))
        return rc;
    if (rd8(t, TIS_STS) & STS_EXPECT)
        return -EIO; /* TPM still wants data */
    wr8(t, TIS_STS, STS_GO);
    return 0;
}

static long read_fifo(struct tis *t, uint8_t *buf, size_t want)
{
    size_t got = 0;
    while (got < want) {
        if (wait_sts(t, STS_VALID | STS_DATA_AVAIL, t->timeout_c_ms, 0))
            return -ETIMEDOUT;
        unsigned burst = burst_count(t);
        if (!burst)
            return -EIO;
        while (burst-- && got < want)
            buf[got++] = rd8(t, TIS_DATA_FIFO);
    }
    return (long)got;
}

static long recv_response(struct tis *t, uint8_t *resp, size_t max)
{
    long rc;
    if ((rc = wait_sts(t, STS_VALID | STS_DATA_AVAIL, t->timeout_long_ms, INT_DATA_AVAIL)))
        return rc;
    if ((rc = read_fifo(t, resp, 10)) < 0)
        return rc;
    uint32_t size = (uint32_t)resp[2] << 24 | (uint32_t)resp[3] << 16 | (uint32_t)resp[4] << 8 | resp[5];
    if (size < 10 || size > max)
        return -EMSGSIZE;
    if ((rc = read_fifo(t, resp + 10, size - 10)) < 0)
        return rc;
    if (wait_sts(t, STS_VALID, t->timeout_c_ms, 0) == 0 && (rd8(t, TIS_STS) & STS_DATA_AVAIL))
        return -EIO; /* more data than the header announced */
    return (long)size;
}

long tis_transmit(struct tis *t, const uint8_t *cmd, size_t len, uint8_t *resp, size_t max)
{
    uint64_t t0 = now_ns();
    long rc;

    if (len < 10 || len > TPM_BUFSIZE)
        return -EINVAL;
    if ((rc = request_locality(t)))
        goto out;
    /* Never resend the command: a repeated PCR_Extend would change the PCR twice. */
    if ((rc = send_command(t, cmd, len)) == 0) {
        rc = recv_response(t, resp, max);
        for (int retry = 0; rc == -EIO && retry < 2; retry++) {
            wr8(t, TIS_STS, STS_RESPONSE_RETRY); /* TPM resends the same response */
            rc = recv_response(t, resp, max);
        }
    }
    tis_cancel(t); /* back to idle: commandReady */
    release_locality(t);
out:
    t->stats.commands++;
    if (rc < 0) {
        t->stats.errors++;
        if (rc == -ETIMEDOUT)
            tis_cancel(t);
    }
    t->stats.last_ns = now_ns() - t0;
    if (t->stats.last_ns > t->stats.max_ns)
        t->stats.max_ns = t->stats.last_ns;
    return rc;
}
