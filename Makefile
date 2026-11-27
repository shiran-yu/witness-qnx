# SPDX-License-Identifier: Apache-2.0
# Cross-build Witness for QNX 8.0 with the SDP toolchain (source qnxsdp-env.sh first).
# make            -> build/x86_64/...
# make ARCH=aarch64le
ARCH ?= x86_64
ifeq ($(ARCH),x86_64)
QCC_TARGET = gcc_ntox86_64
else
QCC_TARGET = gcc_ntoaarch64le
endif
CC = qcc -V$(QCC_TARGET)
CFLAGS = -O2 -g -Wall -Wextra -Werror -std=gnu11 -D_QNX_SOURCE -fstack-protector-strong -D_FORTIFY_SOURCE=2
OUT = build/$(ARCH)

BINS = $(OUT)/dev-tpm-tis $(OUT)/tpm-raw $(OUT)/libtss2-tcti-witness.so.0 $(OUT)/witness-measure

all: $(BINS)

$(OUT):
	mkdir -p $@

$(OUT)/dev-tpm-tis: driver/main.c driver/tis.c driver/tis.h | $(OUT)
	$(CC) $(CFLAGS) -o $@ driver/main.c driver/tis.c

$(OUT)/tpm-raw: tools/tpm-raw.c | $(OUT)
	$(CC) $(CFLAGS) -o $@ tools/tpm-raw.c

$(OUT)/libtss2-tcti-witness.so.0: tcti/tcti-witness.c | $(OUT)
	$(CC) $(CFLAGS) -shared -fPIC -Wl,-soname,libtss2-tcti-witness.so.0 -o $@ tcti/tcti-witness.c

$(OUT)/witness-measure: tools/witness-measure.c lib/sha256.c lib/sha256.h | $(OUT)
	$(CC) $(CFLAGS) -Ilib -o $@ tools/witness-measure.c lib/sha256.c

clean:
	rm -rf build

.PHONY: all clean
