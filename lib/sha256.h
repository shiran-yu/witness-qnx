/* SPDX-License-Identifier: Apache-2.0 */
/* Minimal SHA-256 (FIPS 180-4), no dependencies, used for file measurement. */
#ifndef WITNESS_SHA256_H
#define WITNESS_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_LEN 32

typedef struct {
    uint32_t h[8];
    uint64_t len;
    uint8_t buf[64];
    size_t fill;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t n);
void sha256_final(sha256_ctx *c, uint8_t out[SHA256_LEN]);
void sha256(const void *data, size_t n, uint8_t out[SHA256_LEN]);
/* Hash a whole file; returns 0 on success, -1 (errno set) on failure. */
int sha256_file(const char *path, uint8_t out[SHA256_LEN]);

#endif
