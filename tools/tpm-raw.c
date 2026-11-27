/* SPDX-License-Identifier: Apache-2.0 */
/* tpm-raw: send one hex-encoded TPM2 command to a raw TPM device and print the response in hex.
 * Example (TPM2_GetRandom 8 bytes):  tpm-raw 80010000000c0000017b0008 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *dev = getenv("TPM_DEVICE") ? getenv("TPM_DEVICE") : "/dev/tpm0";
    uint8_t cmd[4096], resp[4096];
    size_t len = 0;

    if (argc != 2 || strlen(argv[1]) % 2 || strlen(argv[1]) / 2 > sizeof cmd) {
        fprintf(stderr, "usage: tpm-raw <command-hex>   (device: $TPM_DEVICE or /dev/tpm0)\n");
        return 2;
    }
    for (const char *p = argv[1]; *p; p += 2) {
        unsigned v;
        if (sscanf(p, "%2x", &v) != 1) {
            fprintf(stderr, "tpm-raw: bad hex\n");
            return 2;
        }
        cmd[len++] = (uint8_t)v;
    }
    int fd = open(dev, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "tpm-raw: open %s: %s\n", dev, strerror(errno));
        return 1;
    }
    if (write(fd, cmd, len) != (ssize_t)len) {
        fprintf(stderr, "tpm-raw: write: %s\n", strerror(errno));
        return 1;
    }
    ssize_t n = read(fd, resp, sizeof resp);
    if (n < 10) {
        fprintf(stderr, "tpm-raw: read: %s\n", n < 0 ? strerror(errno) : "short response");
        return 1;
    }
    for (ssize_t i = 0; i < n; i++)
        printf("%02x", resp[i]);
    printf("\n");
    unsigned rc = (unsigned)resp[6] << 24 | (unsigned)resp[7] << 16 | (unsigned)resp[8] << 8 | resp[9];
    if (rc)
        fprintf(stderr, "tpm-raw: TPM response code 0x%x\n", rc);
    close(fd);
    return rc ? 3 : 0;
}
