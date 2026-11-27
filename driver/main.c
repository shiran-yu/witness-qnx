/* SPDX-License-Identifier: Apache-2.0 */
/* dev-tpm-tis: QNX 8.0 resource manager for a TPM 2.0 on the TIS/FIFO interface.
 *
 * Presents /dev/tpm0 with the same semantics as the Linux raw TPM device: write() one complete
 * TPM2 command, then read() its response. The QNX TCG stack reaches it through libtcti_witness
 * (loaded by tabrm, which provides /dev/tpmrm0 with session and object virtualisation).
 *
 * Single-threaded on purpose: the TPM executes one command at a time, and QNX message passing
 * already queues waiting clients in priority order and runs this server at the priority of the
 * client it is serving, so a high-priority caller is next in line without a lock or a queue here. */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/procmgr.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tis.h"

struct tpm_ocb;
#define IOFUNC_OCB_T struct tpm_ocb
#define RESMGR_OCB_T struct tpm_ocb
#include <sys/dispatch.h>
#include <sys/iofunc.h>

struct tpm_ocb {
    iofunc_ocb_t hdr;
    size_t resp_len; /* bytes of the pending response */
    size_t resp_off; /* bytes already read */
    uint8_t resp[TPM_BUFSIZE];
};

static struct tis tpm;
static iofunc_attr_t tpm_attr;
static iofunc_notify_t notify_list[3];
static uint8_t cmd_buf[TPM_BUFSIZE];
static int verbose;

static IOFUNC_OCB_T *ocb_calloc(resmgr_context_t *ctp, IOFUNC_ATTR_T *attr)
{
    (void)ctp; (void)attr;
    return calloc(1, sizeof(struct tpm_ocb));
}

static void ocb_free(IOFUNC_OCB_T *ocb)
{
    memset(ocb->resp, 0, sizeof ocb->resp); /* responses can hold unsealed secrets */
    free(ocb);
}

static iofunc_funcs_t ocb_funcs = {2, ocb_calloc, ocb_free, NULL, NULL, NULL};
static iofunc_mount_t mountpoint = {.funcs = &ocb_funcs};

static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

static int io_write(resmgr_context_t *ctp, io_write_t *msg, RESMGR_OCB_T *ocb)
{
    int status = iofunc_write_verify(ctp, msg, &ocb->hdr, NULL);
    if (status != EOK)
        return status;
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE)
        return ENOSYS;

    size_t nbytes = _IO_WRITE_GET_NBYTES(msg);
    if (nbytes < 10 || nbytes > sizeof cmd_buf)
        return EINVAL;
    if (resmgr_msgget(ctp, cmd_buf, nbytes, sizeof(msg->i)) != (ssize_t)nbytes)
        return EFAULT;
    if (be32(cmd_buf + 2) != nbytes)
        return EINVAL; /* the header's commandSize must match the write */

    if (ocb->resp_off < ocb->resp_len && verbose)
        fprintf(stderr, "dev-tpm-tis: discarding %zu unread response bytes\n", ocb->resp_len - ocb->resp_off);
    ocb->resp_len = ocb->resp_off = 0;

    long r = tis_transmit(&tpm, cmd_buf, nbytes, ocb->resp, sizeof ocb->resp);
    if (verbose)
        fprintf(stderr, "dev-tpm-tis: cc=0x%03" PRIx32 " -> %s%ld (%" PRIu64 " us)\n", be32(cmd_buf + 6),
                r < 0 ? "error " : "rc ok, len ", r < 0 ? -r : r, tpm.stats.last_ns / 1000);
    if (r < 0)
        return (int)-r;
    ocb->resp_len = (size_t)r;
    iofunc_notify_trigger(notify_list, 1, IOFUNC_NOTIFY_INPUT);
    _IO_SET_WRITE_NBYTES(ctp, nbytes);
    return EOK;
}

static int io_read(resmgr_context_t *ctp, io_read_t *msg, RESMGR_OCB_T *ocb)
{
    int status = iofunc_read_verify(ctp, msg, &ocb->hdr, NULL);
    if (status != EOK)
        return status;
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE)
        return ENOSYS;

    size_t want = _IO_READ_GET_NBYTES(msg);
    size_t left = ocb->resp_len - ocb->resp_off;
    size_t n = want < left ? want : left;
    SETIOV(ctp->iov, ocb->resp + ocb->resp_off, n);
    ocb->resp_off += n;
    if (ocb->resp_off == ocb->resp_len)
        ocb->resp_len = ocb->resp_off = 0;
    _IO_SET_READ_NBYTES(ctp, n);
    return _RESMGR_NPARTS(n ? 1 : 0);
}

static int io_notify(resmgr_context_t *ctp, io_notify_t *msg, RESMGR_OCB_T *ocb)
{
    int trig = _NOTIFY_COND_OUTPUT; /* a command can always be written */
    if (ocb->resp_off < ocb->resp_len)
        trig |= _NOTIFY_COND_INPUT;
    return iofunc_notify(ctp, msg, notify_list, trig, NULL, NULL);
}

static int io_close_ocb(resmgr_context_t *ctp, void *reserved, RESMGR_OCB_T *ocb)
{
    iofunc_notify_remove(ctp, notify_list);
    return iofunc_close_ocb_default(ctp, reserved, &ocb->hdr);
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [-a paddr] [-i irq] [-n path] [-m mode] [-u uid] [-g gid] [-f] [-v]\n"
            "  -a paddr  TIS locality-0 base (default 0x%llx)\n"
            "  -i irq    interrupt line (QEMU tpm-tis: 5); default: polled\n"
            "  -n path   device path (default /dev/tpm0)\n"
            "  -m mode   octal permissions (default 0600)\n"
            "  -u/-g     owner uid/gid of the device node (e.g. the tabrm user)\n"
            "  -f        stay in the foreground\n"
            "  -v        log every command (code, result, duration)\n",
            argv0, (unsigned long long)TIS_DEFAULT_BASE);
}

int main(int argc, char **argv)
{
    uint64_t paddr = TIS_DEFAULT_BASE;
    int irq = -1, foreground = 0, opt;
    const char *path = "/dev/tpm0";
    mode_t mode = 0600;
    uid_t uid = 0;
    gid_t gid = 0;

    while ((opt = getopt(argc, argv, "a:i:n:m:u:g:fvh")) != -1) {
        switch (opt) {
        case 'a': paddr = strtoull(optarg, NULL, 0); break;
        case 'i': irq = atoi(optarg); break;
        case 'n': path = optarg; break;
        case 'm': mode = (mode_t)strtoul(optarg, NULL, 8); break;
        case 'u': uid = (uid_t)atoi(optarg); break;
        case 'g': gid = (gid_t)atoi(optarg); break;
        case 'f': foreground = 1; break;
        case 'v': verbose++; break;
        default: usage(argv[0]); return opt == 'h' ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    }

    int rc = tis_open(&tpm, paddr, irq, 1);
    if (rc) {
        fprintf(stderr, "dev-tpm-tis: no usable TPM at 0x%llx: %s\n", (unsigned long long)paddr, strerror(-rc));
        return EXIT_FAILURE;
    }
    tpm.verbose = verbose;

    dispatch_t *dpp = dispatch_create();
    if (!dpp) {
        perror("dev-tpm-tis: dispatch_create");
        return EXIT_FAILURE;
    }
    resmgr_attr_t rattr;
    memset(&rattr, 0, sizeof rattr);
    rattr.nparts_max = 1;
    rattr.msg_max_size = TPM_BUFSIZE + sizeof(io_write_t);

    resmgr_connect_funcs_t connect_funcs;
    resmgr_io_funcs_t io_funcs;
    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &connect_funcs, _RESMGR_IO_NFUNCS, &io_funcs);
    io_funcs.read = io_read;
    io_funcs.write = io_write;
    io_funcs.notify = io_notify;
    io_funcs.close_ocb = io_close_ocb;

    iofunc_attr_init(&tpm_attr, S_IFCHR | mode, NULL, NULL);
    tpm_attr.uid = uid;
    tpm_attr.gid = gid;
    tpm_attr.mount = &mountpoint;
    IOFUNC_NOTIFY_INIT(notify_list);

    if (resmgr_attach(dpp, &rattr, path, _FTYPE_ANY, 0, &connect_funcs, &io_funcs, &tpm_attr) == -1) {
        fprintf(stderr, "dev-tpm-tis: resmgr_attach(%s): %s\n", path, strerror(errno));
        return EXIT_FAILURE;
    }
    if (!foreground && procmgr_daemon(EXIT_SUCCESS, PROCMGR_DAEMON_NOCLOSE | PROCMGR_DAEMON_NODEVNULL) == -1)
        perror("dev-tpm-tis: procmgr_daemon");

    dispatch_context_t *ctp = dispatch_context_alloc(dpp);
    for (;;) {
        if ((ctp = dispatch_block(ctp)) == NULL) {
            if (errno == EINTR)
                continue;
            perror("dev-tpm-tis: dispatch_block");
            return EXIT_FAILURE;
        }
        dispatch_handler(ctp);
    }
}
