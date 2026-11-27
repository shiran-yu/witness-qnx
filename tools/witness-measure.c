/* SPDX-License-Identifier: Apache-2.0 */
/* witness-measure: measure files into a TPM PCR before they are used, and log each event.
 *
 *   witness-measure -p 8 [-t type] [-l log] [-d /dev/tpm0] file...
 *   witness-measure -p 8 -m manifest      (one path per line, '#' comments)
 *   witness-measure -p 9 -s "text"         (measure a string, e.g. a boot phase marker)
 *
 * Each event: PCR[p] = SHA256(PCR[p] || SHA256(data)), and one log line
 *   <pcr> <sha256-hex> <type> <path-or-text>
 * The log lets a verifier replay the PCR and name the exact file that changed.
 * Depends only on libc so it can run from the IFS before the system partition is trusted. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sha256.h"

#define TPM_RC_INITIALIZE 0x100

static const char *device_path = "/dev/tpm0";
static const char *log_path = "/dev/shmem/witness/eventlog";

static void put32(uint8_t *p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

static int tpm_command(const uint8_t *cmd, size_t len, uint32_t *rc)
{
    uint8_t resp[64];
    int fd = open(device_path, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "witness-measure: open %s: %s\n", device_path, strerror(errno));
        return -1;
    }
    ssize_t n = write(fd, cmd, len);
    if (n == (ssize_t)len)
        n = read(fd, resp, sizeof resp);
    close(fd);
    if (n < 10)
        return -1;
    *rc = get32(resp + 6);
    return 0;
}

static int tpm_startup(void)
{
    static const uint8_t cmd[] = {0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x44, 0, 0}; /* Startup(CLEAR) */
    uint32_t rc;
    return tpm_command(cmd, sizeof cmd, &rc) == 0 && (rc == 0 || rc == TPM_RC_INITIALIZE) ? 0 : -1;
}

/* TPM2_PCR_Extend with an empty password session (PCRs 0-15 have empty auth by default). */
static int pcr_extend(unsigned pcr, const uint8_t digest[SHA256_LEN])
{
    uint8_t cmd[65];
    uint8_t *p = cmd;
    *p++ = 0x80; *p++ = 0x02;           /* TPM_ST_SESSIONS */
    put32(p, sizeof cmd); p += 4;
    put32(p, 0x182); p += 4;            /* TPM_CC_PCR_Extend */
    put32(p, pcr); p += 4;              /* pcrHandle */
    put32(p, 9); p += 4;                /* authorizationSize */
    put32(p, 0x40000009); p += 4;       /* TPM_RS_PW */
    *p++ = 0; *p++ = 0;                 /* nonce: empty */
    *p++ = 0;                           /* sessionAttributes */
    *p++ = 0; *p++ = 0;                 /* hmac: empty password */
    put32(p, 1); p += 4;                /* TPML_DIGEST_VALUES.count */
    *p++ = 0x00; *p++ = 0x0B;           /* TPM_ALG_SHA256 */
    memcpy(p, digest, SHA256_LEN);

    uint32_t rc;
    for (int attempt = 0; attempt < 2; attempt++) {
        if (tpm_command(cmd, sizeof cmd, &rc))
            return -1;
        if (rc == TPM_RC_INITIALIZE && attempt == 0 && tpm_startup() == 0)
            continue; /* no firmware sent TPM2_Startup (e.g. direct -kernel boot) */
        break;
    }
    if (rc) {
        fprintf(stderr, "witness-measure: PCR_Extend(%u) failed, TPM rc 0x%x\n", pcr, rc);
        return -1;
    }
    return 0;
}

static int log_event(unsigned pcr, const uint8_t digest[SHA256_LEN], const char *type, const char *what)
{
    char dir[256];
    snprintf(dir, sizeof dir, "%s", log_path);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) {
        *slash = '\0';
        mkdir(dir, 0755);
    }
    FILE *f = fopen(log_path, "a");
    if (!f)
        return -1;
    fprintf(f, "%u ", pcr);
    for (int i = 0; i < SHA256_LEN; i++)
        fprintf(f, "%02x", digest[i]);
    fprintf(f, " %s %s\n", type, what);
    fclose(f);
    chmod(log_path, 0644);
    return 0;
}

static int measure_digest(unsigned pcr, const uint8_t digest[SHA256_LEN], const char *type, const char *what)
{
    /* Extend first: if logging then fails, the PCR still records the event and verification fails closed. */
    if (pcr_extend(pcr, digest))
        return -1;
    return log_event(pcr, digest, type, what);
}

static int measure_file(unsigned pcr, const char *type, const char *path)
{
    uint8_t digest[SHA256_LEN];
    if (sha256_file(path, digest)) {
        /* A missing file is itself evidence: measure the absence so the verifier sees it. */
        static const char missing[] = "witness:missing";
        sha256(missing, sizeof missing - 1, digest);
        fprintf(stderr, "witness-measure: %s: %s (measured as missing)\n", path, strerror(errno));
        return measure_digest(pcr, digest, "missing", path) ? -1 : 1;
    }
    return measure_digest(pcr, digest, type, path);
}

static int measure_manifest(unsigned pcr, const char *type, const char *manifest)
{
    FILE *f = fopen(manifest, "r");
    char line[1024];
    int failures = 0;
    if (!f) {
        fprintf(stderr, "witness-measure: %s: %s\n", manifest, strerror(errno));
        return -1;
    }
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *path = line + strspn(line, " \t");
        if (*path == '\0' || *path == '#')
            continue;
        if (measure_file(pcr, type, path) < 0)
            failures++;
    }
    fclose(f);
    return failures ? -1 : 0;
}

static void usage(void)
{
    fprintf(stderr, "usage: witness-measure -p pcr [-t type] [-l log] [-d device] (-m manifest | -s text | file...)\n");
    exit(2);
}

int main(int argc, char **argv)
{
    int pcr = -1, opt, rc = 0;
    const char *type = "file", *manifest = NULL, *text = NULL;

    while ((opt = getopt(argc, argv, "p:t:l:d:m:s:")) != -1) {
        switch (opt) {
        case 'p': pcr = atoi(optarg); break;
        case 't': type = optarg; break;
        case 'l': log_path = optarg; break;
        case 'd': device_path = optarg; break;
        case 'm': manifest = optarg; break;
        case 's': text = optarg; break;
        default: usage();
        }
    }
    if (pcr < 0 || pcr > 23 || (!manifest && !text && optind >= argc))
        usage();

    if (text) {
        uint8_t digest[SHA256_LEN];
        sha256(text, strlen(text), digest);
        rc |= measure_digest((unsigned)pcr, digest, "string", text) ? 1 : 0;
    }
    if (manifest)
        rc |= measure_manifest((unsigned)pcr, type, manifest) ? 1 : 0;
    for (int i = optind; i < argc; i++)
        rc |= measure_file((unsigned)pcr, type, argv[i]) < 0 ? 1 : 0;
    return rc;
}
