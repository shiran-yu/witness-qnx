/* SPDX-License-Identifier: Apache-2.0 */
/* libtss2-tcti-witness: a standard TCG TSS2 TCTI (v2) for a raw TPM device node served by
 * dev-tpm-tis (default /dev/tpm0). Exposes Tss2_Tcti_Info, so it can be loaded by:
 *   - QNX tabrm:            "tcti_module_name": "/usr/lib/libtss2-tcti-witness.so.0"
 *   - tss2-tctildr / tools:  TPM2TOOLS_TCTI=witness:/dev/tpm0
 * Config string: the device path (empty or NULL means /dev/tpm0). */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <tss2/tss2_tcti.h>

#define WITNESS_TCTI_MAGIC 0x5749544e45535331ULL /* "WITNESS1" */
#define WITNESS_DEFAULT_DEVICE "/dev/tpm0"
#define WITNESS_MAX_RESPONSE 4096

enum tcti_state { STATE_TRANSMIT, STATE_RECEIVE };

typedef struct {
    TSS2_TCTI_CONTEXT_COMMON_V2 common;
    int fd;
    enum tcti_state state;
} witness_tcti_context;

static witness_tcti_context *context_cast(TSS2_TCTI_CONTEXT *tcti_context)
{
    if (tcti_context == NULL || TSS2_TCTI_MAGIC(tcti_context) != WITNESS_TCTI_MAGIC)
        return NULL;
    return (witness_tcti_context *)tcti_context;
}

static TSS2_RC witness_transmit(TSS2_TCTI_CONTEXT *tcti_context, size_t size, const uint8_t *command)
{
    witness_tcti_context *context = context_cast(tcti_context);
    if (context == NULL)
        return TSS2_TCTI_RC_BAD_CONTEXT;
    if (command == NULL)
        return TSS2_TCTI_RC_BAD_REFERENCE;
    if (context->state != STATE_TRANSMIT)
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    if (size < 10 || size > WITNESS_MAX_RESPONSE)
        return TSS2_TCTI_RC_BAD_VALUE;

    ssize_t written;
    do {
        written = write(context->fd, command, size); /* the driver runs the command during write */
    } while (written < 0 && errno == EINTR);
    if (written != (ssize_t)size)
        return TSS2_TCTI_RC_IO_ERROR;
    context->state = STATE_RECEIVE;
    return TSS2_RC_SUCCESS;
}

static TSS2_RC witness_receive(TSS2_TCTI_CONTEXT *tcti_context, size_t *size, uint8_t *response, int32_t timeout)
{
    witness_tcti_context *context = context_cast(tcti_context);
    if (context == NULL)
        return TSS2_TCTI_RC_BAD_CONTEXT;
    if (size == NULL)
        return TSS2_TCTI_RC_BAD_REFERENCE;
    if (context->state != STATE_RECEIVE)
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    if (response == NULL) {
        *size = WITNESS_MAX_RESPONSE; /* size query, as tss2 callers expect */
        return TSS2_RC_SUCCESS;
    }
    if (*size < 10)
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;

    if (timeout != TSS2_TCTI_TIMEOUT_BLOCK) {
        struct pollfd poll_descriptor = {.fd = context->fd, .events = POLLIN};
        int ready = poll(&poll_descriptor, 1, timeout);
        if (ready == 0)
            return TSS2_TCTI_RC_TRY_AGAIN;
        if (ready < 0)
            return TSS2_TCTI_RC_IO_ERROR;
    }

    ssize_t received;
    do {
        received = read(context->fd, response, *size);
    } while (received < 0 && errno == EINTR);
    if (received < 10) {
        context->state = STATE_TRANSMIT;
        return TSS2_TCTI_RC_IO_ERROR;
    }
    uint32_t announced = (uint32_t)response[2] << 24 | (uint32_t)response[3] << 16 | (uint32_t)response[4] << 8 | response[5];
    if (announced != (uint32_t)received) {
        context->state = STATE_TRANSMIT;
        return announced > *size ? TSS2_TCTI_RC_INSUFFICIENT_BUFFER : TSS2_TCTI_RC_MALFORMED_RESPONSE;
    }
    *size = (size_t)received;
    context->state = STATE_TRANSMIT;
    return TSS2_RC_SUCCESS;
}

static void witness_finalize(TSS2_TCTI_CONTEXT *tcti_context)
{
    witness_tcti_context *context = context_cast(tcti_context);
    if (context == NULL)
        return;
    if (context->fd >= 0)
        close(context->fd);
    context->fd = -1;
    context->common.v1.magic = 0;
}

static TSS2_RC witness_cancel(TSS2_TCTI_CONTEXT *tcti_context)
{
    (void)tcti_context;
    return TSS2_TCTI_RC_NOT_IMPLEMENTED; /* commands complete synchronously inside write() */
}

static TSS2_RC witness_get_poll_handles(TSS2_TCTI_CONTEXT *tcti_context, TSS2_TCTI_POLL_HANDLE *handles, size_t *num_handles)
{
    witness_tcti_context *context = context_cast(tcti_context);
    if (context == NULL)
        return TSS2_TCTI_RC_BAD_CONTEXT;
    if (num_handles == NULL)
        return TSS2_TCTI_RC_BAD_REFERENCE;
    if (handles != NULL && *num_handles < 1)
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    *num_handles = 1;
    if (handles != NULL) {
        handles->fd = context->fd;
        handles->events = POLLIN | POLLOUT;
        handles->revents = 0;
    }
    return TSS2_RC_SUCCESS;
}

static TSS2_RC witness_set_locality(TSS2_TCTI_CONTEXT *tcti_context, uint8_t locality)
{
    if (context_cast(tcti_context) == NULL)
        return TSS2_TCTI_RC_BAD_CONTEXT;
    return locality == 0 ? TSS2_RC_SUCCESS : TSS2_TCTI_RC_NOT_IMPLEMENTED; /* driver uses locality 0 */
}

static TSS2_RC witness_make_sticky(TSS2_TCTI_CONTEXT *tcti_context, TPM2_HANDLE *handle, uint8_t sticky)
{
    (void)tcti_context; (void)handle; (void)sticky;
    return TSS2_TCTI_RC_NOT_IMPLEMENTED; /* object lifetime is tabrm's job */
}

TSS2_RC Tss2_Tcti_Witness_Init(TSS2_TCTI_CONTEXT *tcti_context, size_t *size, const char *config)
{
    if (size == NULL)
        return TSS2_TCTI_RC_BAD_VALUE;
    if (tcti_context == NULL) {
        *size = sizeof(witness_tcti_context);
        return TSS2_RC_SUCCESS;
    }
    if (*size < sizeof(witness_tcti_context))
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;

    const char *device = (config != NULL && config[0] != '\0') ? config : WITNESS_DEFAULT_DEVICE;
    int fd = open(device, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return TSS2_TCTI_RC_IO_ERROR;

    witness_tcti_context *context = (witness_tcti_context *)tcti_context;
    memset(context, 0, sizeof *context);
    context->common.v1.magic = WITNESS_TCTI_MAGIC;
    context->common.v1.version = 2;
    context->common.v1.transmit = witness_transmit;
    context->common.v1.receive = witness_receive;
    context->common.v1.finalize = witness_finalize;
    context->common.v1.cancel = witness_cancel;
    context->common.v1.getPollHandles = witness_get_poll_handles;
    context->common.v1.setLocality = witness_set_locality;
    context->common.makeSticky = witness_make_sticky;
    context->fd = fd;
    context->state = STATE_TRANSMIT;
    return TSS2_RC_SUCCESS;
}

static const TSS2_TCTI_INFO witness_tcti_info = {
    .version = 2,
    .name = "witness",
    .description = "TCTI for a raw TPM device node served by the QNX dev-tpm-tis resource manager",
    .config_help = "Path of the raw TPM device node; default " WITNESS_DEFAULT_DEVICE,
    .init = Tss2_Tcti_Witness_Init,
};

const TSS2_TCTI_INFO *Tss2_Tcti_Info(void)
{
    return &witness_tcti_info;
}
