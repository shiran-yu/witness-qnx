/* SPDX-License-Identifier: Apache-2.0 */
/* witnessd: remote-attestation agent for QNX 8.0, built on QNX's own TSS2 ESYS stack.
 *
 * Path: witnessd -> ESYS -> Witness TCTI (linked in) -> dev-tpm-tis /dev/tpm0 -> TPM. After boot it is the
 * only TPM client (the security policy admits no other), so it needs no resource manager. A supervisor
 * process restarts the agent if a request outlives the watchdog.
 *
 * On start it derives the attestation key (AK: ECC P-256, restricted signing, from the endorsement
 * hierarchy, so the same key comes back on every boot of the same TPM) and loads the device key: an
 * ECC P-256 signing key usable only under PolicyAuthorize by the build host's release key (a signed
 * PolicyPCR over PCR 4,5,8,9 plus PolicyNV over the anti-rollback bits, per release), then PolicyPCR over
 * this device's firmware (PCR 0,2,7). So a signature with it over the verifier's nonce proves a
 * released, non-rolled-back boot state, and a fleet service can use it as the device's credential.
 * If no device key exists yet (first boot in the factory), it creates one.
 *
 * Protocol (TCP, one request per connection):  "ATTEST <nonce-hex>\n"  ->  one JSON object
 *   ak_public  TPM2B_PUBLIC (hex)     quote      TPMS_ATTEST (hex)    signature  TPMT_SIGNATURE (hex)
 *   pcrs       PCR 0-9 (sha256, hex)  eventlog   Witness event log    sealed     unsealed|locked|error
 *   device_key {public, signature over SHA256("witness:device-key:" nonce)} or device_key_error */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stddef.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/neutrino.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tcti.h>
#include <openssl/crypto.h>
#include "witness-report.h"

TSS2_RC Tss2_Tcti_Witness_Init(TSS2_TCTI_CONTEXT *tcti_context, size_t *size, const char *config); /* tcti/tcti-witness.c */

#define DEFAULT_PORT 7650
#define QUOTE_PCR_MASK 0x0003FF /* PCR 0-9 */
#define SEAL_PCR_MASK 0x0003B5  /* PCR 0,2,4,5,7 (firmware, boot image, disk, Secure Boot), 8 (system), 9 (apps) */
#define FIRMWARE_PCR_MASK 0x000085 /* PCR 0,2,7: bound per device after PolicyAuthorize (not in the signed policy) */
#define DEVICE_KEY_LABEL "witness:device-key:"
#define WATCHDOG_SECONDS 10 /* longest the TPM work and reply of one request may take */
#define REQUEST_BUDGET_MS 2000 /* a client must send its request line within this */
#define MAX_PENDING 64 /* clients being read at once */
#define AGENT_PRIORITY 8 /* below QNX's default 10; children inherit it */

static ESYS_CONTEXT *esys;
static pthread_mutex_t tpm_lock = PTHREAD_MUTEX_INITIALIZER; /* ESYS is not thread safe: TCP and report threads */
static ESYS_TR attestation_key = ESYS_TR_NONE;
static TPM2B_PUBLIC *attestation_key_public;
static ESYS_TR device_key = ESYS_TR_NONE;
static TPM2B_PUBLIC device_key_public;
static const char *eventlog_path = "/dev/shmem/witness/eventlog";
static const char *state_dir = "/data/var/witness";
static const char *sealed_state = "none";

static void fail(const char *what, TSS2_RC rc)
{
    fprintf(stderr, "witnessd: %s: %s\n", what, Tss2_RC_Decode(rc));
}

static void selection_from_mask(TPML_PCR_SELECTION *selection, uint32_t mask)
{
    memset(selection, 0, sizeof *selection);
    selection->count = 1;
    selection->pcrSelections[0].hash = TPM2_ALG_SHA256;
    selection->pcrSelections[0].sizeofSelect = 3;
    selection->pcrSelections[0].pcrSelect[0] = mask & 0xFF;
    selection->pcrSelections[0].pcrSelect[1] = (mask >> 8) & 0xFF;
    selection->pcrSelections[0].pcrSelect[2] = (mask >> 16) & 0xFF;
}

static TSS2_RC create_attestation_key(void)
{
    TPM2B_SENSITIVE_CREATE sensitive = {0};
    TPM2B_PUBLIC template = {
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT,
            .parameters.eccDetail = {
                .symmetric.algorithm = TPM2_ALG_NULL,
                .scheme = {.scheme = TPM2_ALG_ECDSA, .details.ecdsa.hashAlg = TPM2_ALG_SHA256},
                .curveID = TPM2_ECC_NIST_P256,
                .kdf.scheme = TPM2_ALG_NULL,
            },
        },
    };
    TPM2B_DATA outside_info = {0};
    TPML_PCR_SELECTION creation_pcr = {0};
    return Esys_CreatePrimary(esys, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &sensitive,
                              &template, &outside_info, &creation_pcr, &attestation_key, &attestation_key_public,
                              NULL, NULL, NULL);
}

static TSS2_RC create_storage_key(ESYS_TR *storage_key)
{
    TPM2B_SENSITIVE_CREATE sensitive = {0};
    TPM2B_PUBLIC template = {
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_NODA | TPMA_OBJECT_RESTRICTED |
                                TPMA_OBJECT_DECRYPT,
            .parameters.eccDetail = {
                .symmetric = {.algorithm = TPM2_ALG_AES, .keyBits.aes = 128, .mode.aes = TPM2_ALG_CFB},
                .scheme.scheme = TPM2_ALG_NULL,
                .curveID = TPM2_ECC_NIST_P256,
                .kdf.scheme = TPM2_ALG_NULL,
            },
        },
    };
    TPM2B_DATA outside_info = {0};
    TPML_PCR_SELECTION creation_pcr = {0};
    return Esys_CreatePrimary(esys, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &sensitive,
                              &template, &outside_info, &creation_pcr, storage_key, NULL, NULL, NULL, NULL);
}

/* PolicyPCR over the current values of the seal PCRs, in a trial (digest only) or real session. */
static TSS2_RC pcr_policy_session(TPM2_SE session_type, uint32_t pcr_mask, ESYS_TR *session)
{
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_NULL};
    TSS2_RC rc = Esys_StartAuthSession(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                       NULL, session_type, &symmetric, TPM2_ALG_SHA256, session);
    if (rc != TSS2_RC_SUCCESS)
        return rc;
    TPM2B_DIGEST current_values = {0}; /* empty: the TPM uses the PCRs as they are now */
    TPML_PCR_SELECTION selection;
    selection_from_mask(&selection, pcr_mask);
    rc = Esys_PolicyPCR(esys, *session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &current_values, &selection);
    if (rc != TSS2_RC_SUCCESS)
        Esys_FlushContext(esys, *session);
    return rc;
}

static int write_blob(const char *path, const uint8_t *data, size_t size)
{
    char tmp[256 + sizeof ".tmp"]; /* callers pass paths up to 256 bytes */
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return -1;
    int ok = write(fd, data, size) == (ssize_t)size;
    ok = (fsync(fd) == 0) && ok;
    close(fd);
    return ok && rename(tmp, path) == 0 ? 0 : -1;
}

/* Signed releases. RELEASE_PUB (in the IFS) holds the release public key; when present the device key's
 * policy is PolicyAuthorize(release key), and each release ships a policy file signed by that key:
 * PolicyPCR over its PCRs, then PolicyAuthorize with the signature checked by the TPM. */
#define RELEASE_PUB "/proc/boot/witness-release.pub"
#define RELEASE_POLICY "release-policy" /* in state_dir; signed, so it needs no measurement */
/* Anti-rollback: an NV bit field (bits can be set, never cleared). Release N's signed policy holds
 * PolicyNV(BITCLEAR, bits N..63), and once the TPM has accepted release N witnessd sets bits 0..N-1,
 * so every older release's policy fails in the TPM. Must match host/witness/release.py. */
#define RELEASE_NV_INDEX 0x01005700
#define RELEASE_NV_ATTRIBUTES (TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD | TPMA_NV_NO_DA | (TPM2_NT_BITS << TPMA_NV_TPM2_NT_SHIFT))

struct release {
    uint32_t pcr_mask, number; /* release number 1-63; a policy without one is not accepted */
    uint8_t approved[32], r[32], s[32], x[32], y[32];
    int have_key, have_policy;
};

static int parse_hex(const char *text, uint8_t *out, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        unsigned v;
        if (sscanf(text + 2 * i, "%2x", &v) != 1)
            return -1;
        out[i] = (uint8_t)v;
    }
    return text[2 * size] == '\0' || text[2 * size] == '\n' ? 0 : -1;
}

/* Reads `key value` lines; a file that is absent or malformed leaves the fields unset. */
static void read_release_file(const char *path, struct release *release)
{
    FILE *file = fopen(path, "r");
    char line[256], key[32], value[160];
    int seen = 0;
    while (file && fgets(line, sizeof line, file)) {
        if (sscanf(line, "%31s %159s", key, value) != 2)
            continue;
        if (!strcmp(key, "pcr_mask") && sscanf(value, "%x", &release->pcr_mask) == 1)
            seen |= 1;
        else if (!strcmp(key, "approved_policy") && !parse_hex(value, release->approved, 32))
            seen |= 2;
        else if (!strcmp(key, "signature_r") && !parse_hex(value, release->r, 32))
            seen |= 4;
        else if (!strcmp(key, "signature_s") && !parse_hex(value, release->s, 32))
            seen |= 8;
        else if (!strcmp(key, "release_x") && !parse_hex(value, release->x, 32))
            seen |= 16;
        else if (!strcmp(key, "release_y") && !parse_hex(value, release->y, 32))
            seen |= 32;
        else if (!strcmp(key, "release_number") && sscanf(value, "%u", &release->number) != 1)
            release->number = 100; /* malformed: out of range below */
    }
    if (file)
        fclose(file);
    release->have_key = (seen & 48) == 48;
    /* numbered releases only: an unnumbered signed policy would skip PolicyNV and stay a rollback target */
    release->have_policy = (seen & 63) == 63 && (release->pcr_mask & ~SEAL_PCR_MASK) == 0 && release->number >= 1 &&
                           release->number <= 63;
}

static struct release read_release(void)
{
    struct release release = {0}, policy = {0};
    char path[256];
    read_release_file(RELEASE_PUB, &release);
    snprintf(path, sizeof path, "%s/%s", state_dir, RELEASE_POLICY);
    read_release_file(path, &policy);
    /* the policy counts only if it names the release key that the image trusts */
    if (release.have_key && policy.have_policy && !memcmp(policy.x, release.x, 32) && !memcmp(policy.y, release.y, 32))
        return policy;
    return release;
}

/* The release public key, loaded as an external key in the owner hierarchy (so its tickets are valid). */
static TSS2_RC load_release_key(const struct release *release, ESYS_TR *key, TPM2B_NAME **name)
{
    TPM2B_PUBLIC public = {
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_USERWITHAUTH,
            .parameters.eccDetail = {
                .symmetric.algorithm = TPM2_ALG_NULL,
                .scheme = {.scheme = TPM2_ALG_ECDSA, .details.ecdsa.hashAlg = TPM2_ALG_SHA256},
                .curveID = TPM2_ECC_NIST_P256,
                .kdf.scheme = TPM2_ALG_NULL,
            },
            .unique.ecc = {.x.size = 32, .y.size = 32},
        },
    };
    memcpy(public.publicArea.unique.ecc.x.buffer, release->x, 32);
    memcpy(public.publicArea.unique.ecc.y.buffer, release->y, 32);
    TSS2_RC rc = Esys_LoadExternal(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, &public, ESYS_TR_RH_OWNER, key);
    if (rc == TSS2_RC_SUCCESS && name && (rc = Esys_TR_GetName(esys, *key, name)) != TSS2_RC_SUCCESS)
        Esys_FlushContext(esys, *key);
    return rc;
}

/* PolicyPCR over `mask` with the PCRs as they are now */
static TSS2_RC policy_pcr(ESYS_TR session, uint32_t mask)
{
    TPM2B_DIGEST current_values = {0};
    TPML_PCR_SELECTION selection;
    selection_from_mask(&selection, mask);
    return Esys_PolicyPCR(esys, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &current_values, &selection);
}

/* The anti-rollback NV index; defined (all bits clear) on first use. Close the handle with Esys_TR_Close. */
static TSS2_RC release_counter(ESYS_TR *nv)
{
    if (Esys_TR_FromTPMPublic(esys, RELEASE_NV_INDEX, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, nv) == TSS2_RC_SUCCESS) {
        TPM2B_NV_PUBLIC *public = NULL;
        TSS2_RC rc = Esys_NV_ReadPublic(esys, *nv, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &public, NULL);
        /* defined but never written (power lost after DefineSpace): PolicyNV would fail for good */
        if (rc == TSS2_RC_SUCCESS && !(public->nvPublic.attributes & TPMA_NV_WRITTEN))
            rc = Esys_NV_SetBits(esys, *nv, *nv, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, 0);
        Esys_Free(public);
        if (rc != TSS2_RC_SUCCESS)
            Esys_TR_Close(esys, nv);
        return rc;
    }
    TPM2B_AUTH auth = {0};
    TPM2B_NV_PUBLIC public = {
        .nvPublic = {.nvIndex = RELEASE_NV_INDEX, .nameAlg = TPM2_ALG_SHA256, .attributes = RELEASE_NV_ATTRIBUTES,
                     .dataSize = 8},
    };
    TSS2_RC rc = Esys_NV_DefineSpace(esys, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &auth,
                                     &public, nv);
    if (rc == TSS2_RC_SUCCESS) /* first write: the index exists with no bit set (release 1 and later pass) */
        rc = Esys_NV_SetBits(esys, *nv, *nv, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, 0);
    if (rc == TSS2_RC_SUCCESS)
        fprintf(stderr, "witnessd: anti-rollback NV index 0x%x defined\n", RELEASE_NV_INDEX);
    return rc;
}

/* PolicyNV: no bit N..63 is set, i.e. no release newer than N has run on this TPM */
static TSS2_RC policy_release_number(ESYS_TR session, uint32_t number)
{
    ESYS_TR nv;
    TSS2_RC rc = release_counter(&nv);
    if (rc != TSS2_RC_SUCCESS)
        return rc;
    uint64_t newer = ~((UINT64_C(1) << number) - 1);
    TPM2B_OPERAND operand = {.size = 8};
    for (int i = 0; i < 8; i++)
        operand.buffer[i] = (uint8_t)(newer >> (56 - 8 * i));
    rc = Esys_PolicyNV(esys, nv, nv, session, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &operand, 0,
                       TPM2_EO_BITCLEAR);
    Esys_TR_Close(esys, &nv);
    return rc;
}

/* After the TPM accepted release N: set bits 0..N-1, so releases older than N fail from now on. */
static void record_release_number(uint32_t number)
{
    ESYS_TR nv;
    TPM2B_MAX_NV_BUFFER *data = NULL;
    uint64_t bits = (UINT64_C(1) << number) - 1, current = 0;
    if (!number || release_counter(&nv) != TSS2_RC_SUCCESS)
        return;
    if (Esys_NV_Read(esys, nv, nv, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, 8, 0, &data) == TSS2_RC_SUCCESS &&
        data->size == 8)
        for (int i = 0; i < 8; i++)
            current = current << 8 | data->buffer[i];
    Esys_Free(data);
    if ((current & bits) != bits) { /* write only when it changes (NV wear) */
        TSS2_RC rc = Esys_NV_SetBits(esys, nv, nv, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, bits);
        if (rc != TSS2_RC_SUCCESS)
            fail("record release number", rc);
        else
            fprintf(stderr, "witnessd: release %u recorded: older releases can no longer use the device key\n", number);
    }
    Esys_TR_Close(esys, &nv);
}

/* In a policy session already past PolicyPCR: have the TPM check the release signature, then PolicyAuthorize. */
static TSS2_RC authorize_release(ESYS_TR session, const struct release *release)
{
    ESYS_TR key;
    TPM2B_NAME *name = NULL;
    TPM2B_DIGEST *a_hash = NULL;
    TPMT_TK_HASHCHECK *hash_ticket = NULL;
    TPMT_TK_VERIFIED *verified = NULL;
    TPM2B_MAX_BUFFER approved_buffer = {.size = 32};
    memcpy(approved_buffer.buffer, release->approved, 32);
    TSS2_RC rc = load_release_key(release, &key, &name);
    if (rc != TSS2_RC_SUCCESS)
        return rc;
    rc = Esys_Hash(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &approved_buffer, TPM2_ALG_SHA256, ESYS_TR_RH_NULL,
                   &a_hash, &hash_ticket);
    if (rc == TSS2_RC_SUCCESS) {
        TPMT_SIGNATURE signature = {.sigAlg = TPM2_ALG_ECDSA};
        signature.signature.ecdsa.hash = TPM2_ALG_SHA256;
        signature.signature.ecdsa.signatureR.size = 32;
        signature.signature.ecdsa.signatureS.size = 32;
        memcpy(signature.signature.ecdsa.signatureR.buffer, release->r, 32);
        memcpy(signature.signature.ecdsa.signatureS.buffer, release->s, 32);
        rc = Esys_VerifySignature(esys, key, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, a_hash, &signature, &verified);
    }
    if (rc == TSS2_RC_SUCCESS) {
        TPM2B_DIGEST approved = {.size = 32};
        TPM2B_NONCE policy_ref = {0};
        memcpy(approved.buffer, release->approved, 32);
        rc = Esys_PolicyAuthorize(esys, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &approved, &policy_ref, name,
                                  verified);
    }
    Esys_FlushContext(esys, key);
    Esys_Free(name);
    Esys_Free(a_hash);
    Esys_Free(hash_ticket);
    Esys_Free(verified);
    return rc;
}

/* First boot: a P-256 signing key, created inside the TPM, usable only through its policy: PolicyAuthorize by
 * the release key when the image carries one, else PolicyPCR over SEAL_PCR_MASK. */
static TSS2_RC create_device_key(ESYS_TR storage_key, const char *blob_path)
{
    ESYS_TR trial;
    TPM2B_DIGEST *policy = NULL;
    TPM2B_PRIVATE *sealed_private = NULL;
    TPM2B_PUBLIC *sealed_public = NULL;
    struct release release = read_release();
    TSS2_RC rc;
    if (release.have_key) {
        ESYS_TR key;
        TPM2B_NAME *name = NULL;
        rc = load_release_key(&release, &key, &name);
        if (rc != TSS2_RC_SUCCESS)
            return rc;
        Esys_FlushContext(esys, key);
        /* trial: PolicyAuthorize(release key), then PolicyPCR over this device's firmware PCRs as they are now
         * (a trial session does not check the approved policy or the ticket) */
        TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_NULL};
        rc = Esys_StartAuthSession(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL,
                                   TPM2_SE_TRIAL, &symmetric, TPM2_ALG_SHA256, &trial);
        if (rc == TSS2_RC_SUCCESS) {
            TPM2B_DIGEST approved = {.size = 32};
            TPM2B_NONCE policy_ref = {0};
            TPMT_TK_VERIFIED no_ticket = {.tag = TPM2_ST_VERIFIED, .hierarchy = TPM2_RH_NULL};
            rc = Esys_PolicyAuthorize(esys, trial, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &approved, &policy_ref,
                                      name, &no_ticket);
            if (rc == TSS2_RC_SUCCESS)
                rc = policy_pcr(trial, FIRMWARE_PCR_MASK);
            if (rc == TSS2_RC_SUCCESS)
                rc = Esys_PolicyGetDigest(esys, trial, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &policy);
            Esys_FlushContext(esys, trial);
        }
        Esys_Free(name);
    } else {
        rc = pcr_policy_session(TPM2_SE_TRIAL, SEAL_PCR_MASK, &trial);
        if (rc != TSS2_RC_SUCCESS)
            return rc;
        rc = Esys_PolicyGetDigest(esys, trial, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &policy);
        Esys_FlushContext(esys, trial);
    }
    if (rc != TSS2_RC_SUCCESS)
        return rc;

    TPM2B_SENSITIVE_CREATE sensitive = {0};
    TPM2B_PUBLIC template = {
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            /* policy-only (no userWithAuth): the PCR policy is the sole way to use it */
            .objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                TPMA_OBJECT_SIGN_ENCRYPT,
            .authPolicy = *policy,
            .parameters.eccDetail = {
                .symmetric.algorithm = TPM2_ALG_NULL,
                .scheme = {.scheme = TPM2_ALG_ECDSA, .details.ecdsa.hashAlg = TPM2_ALG_SHA256},
                .curveID = TPM2_ECC_NIST_P256,
                .kdf.scheme = TPM2_ALG_NULL,
            },
        },
    };
    TPM2B_DATA outside_info = {0};
    TPML_PCR_SELECTION creation_pcr = {0};
    rc = Esys_Create(esys, storage_key, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &sensitive, &template,
                     &outside_info, &creation_pcr, &sealed_private, &sealed_public, NULL, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS)
        goto out;

    uint8_t blob[sizeof(TPM2B_PRIVATE) + sizeof(TPM2B_PUBLIC)];
    size_t offset = 0;
    rc = Tss2_MU_TPM2B_PRIVATE_Marshal(sealed_private, blob, sizeof blob, &offset);
    if (rc == TSS2_RC_SUCCESS)
        rc = Tss2_MU_TPM2B_PUBLIC_Marshal(sealed_public, blob, sizeof blob, &offset);
    if (rc == TSS2_RC_SUCCESS && write_blob(blob_path, blob, offset) != 0) {
        fprintf(stderr, "witnessd: cannot write %s: %s\n", blob_path, strerror(errno));
        rc = TSS2_BASE_RC_IO_ERROR;
    }
out:
    Esys_Free(policy);
    Esys_Free(sealed_private);
    Esys_Free(sealed_public);
    return rc;
}

/* Sign SHA256(label || data) with the device key; the TPM refuses unless the PCR policy holds. The label
 * separates uses: a report signature ("witness:report:") is never a valid attestation ("witness:device-key:"). */
static TSS2_RC device_key_sign(const char *label, const uint8_t *data, size_t size, TPMT_SIGNATURE **signature)
{
    size_t label_size = strlen(label);
    TPM2B_MAX_BUFFER buffer = {.size = (UINT16)(label_size + size)};
    TPM2B_DIGEST *digest = NULL;
    TPMT_TK_HASHCHECK *ticket = NULL;
    if (device_key == ESYS_TR_NONE || label_size + size > sizeof buffer.buffer)
        return TSS2_ESYS_RC_BAD_VALUE;
    memcpy(buffer.buffer, label, label_size);
    memcpy(buffer.buffer + label_size, data, size);
    TSS2_RC rc = Esys_Hash(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &buffer, TPM2_ALG_SHA256, ESYS_TR_RH_NULL,
                           &digest, &ticket);
    if (rc != TSS2_RC_SUCCESS)
        return rc;
    ESYS_TR session;
    struct release release = read_release();
    if (release.have_key && !release.have_policy) {
        Esys_Free(digest);
        Esys_Free(ticket);
        return TSS2_ESYS_RC_BAD_VALUE; /* no signed policy for this release: the key stays locked */
    }
    rc = pcr_policy_session(TPM2_SE_POLICY, release.have_key ? release.pcr_mask : SEAL_PCR_MASK, &session);
    if (rc == TSS2_RC_SUCCESS && release.have_key) {
        rc = policy_release_number(session, release.number); /* the signed policy is PolicyPCR then PolicyNV */
        if (rc == TSS2_RC_SUCCESS)
            rc = authorize_release(session, &release);
        if (rc == TSS2_RC_SUCCESS) /* then this device's enrolled firmware state */
            rc = policy_pcr(session, FIRMWARE_PCR_MASK);
        if (rc != TSS2_RC_SUCCESS)
            Esys_FlushContext(esys, session);
    }
    if (rc == TSS2_RC_SUCCESS) {
        TPMT_SIG_SCHEME scheme = {.scheme = TPM2_ALG_NULL}; /* the key's own ECDSA-SHA256 */
        rc = Esys_Sign(esys, device_key, session, ESYS_TR_NONE, ESYS_TR_NONE, digest, &scheme, ticket, signature);
        Esys_FlushContext(esys, session);
    }
    if (rc == TSS2_RC_SUCCESS && release.have_key) /* the TPM checked this release's signature: record it */
        record_release_number(release.number);
    Esys_Free(digest);
    Esys_Free(ticket);
    return rc;
}

static TSS2_RC load_device_key(ESYS_TR storage_key, const char *blob_path)
{
    uint8_t blob[sizeof(TPM2B_PRIVATE) + sizeof(TPM2B_PUBLIC)];
    int fd = open(blob_path, O_RDONLY);
    if (fd < 0)
        return TSS2_BASE_RC_IO_ERROR;
    ssize_t size = read(fd, blob, sizeof blob);
    close(fd);
    if (size <= 0)
        return TSS2_BASE_RC_IO_ERROR;

    TPM2B_PRIVATE sealed_private = {0}; /* tss2 MU rejects a destination whose size is not 0 */
    TPM2B_PUBLIC sealed_public = {0};
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(blob, (size_t)size, &offset, &sealed_private);
    if (rc == TSS2_RC_SUCCESS)
        rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(blob, (size_t)size, &offset, &sealed_public);
    if (rc != TSS2_RC_SUCCESS)
        return rc;

    rc = Esys_Load(esys, storage_key, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &sealed_private, &sealed_public,
                   &device_key);
    if (rc != TSS2_RC_SUCCESS) {
        fail("load device key", rc);
        device_key = ESYS_TR_NONE;
        return rc;
    }
    device_key_public = sealed_public;
    return TSS2_RC_SUCCESS;
}

static void provision_or_load(void)
{
    char blob_path[256];
    ESYS_TR storage_key;

    mkdir(state_dir, 0700);
    snprintf(blob_path, sizeof blob_path, "%s/device-key.blob", state_dir);
    TSS2_RC rc = create_storage_key(&storage_key);
    if (rc != TSS2_RC_SUCCESS) {
        fail("storage key", rc);
        sealed_state = "error";
        return;
    }
    if (access(blob_path, F_OK) != 0) {
        rc = create_device_key(storage_key, blob_path);
        if (rc != TSS2_RC_SUCCESS)
            fail("create device key", rc);
        else
            fprintf(stderr, "witnessd: provisioned: device key bound to %s\n",
                    read_release().have_key ? "releases signed by the release key" : "PCR 0,2,4,5,7,8,9");
    }
    rc = load_device_key(storage_key, blob_path);
    Esys_FlushContext(esys, storage_key);
    TPMT_SIGNATURE *probe = NULL;
    if (rc == TSS2_RC_SUCCESS)
        rc = device_key_sign(DEVICE_KEY_LABEL, (const uint8_t *)"boot", 4, &probe);
    Esys_Free(probe);
    struct release release = read_release();
    if (rc == TSS2_RC_SUCCESS) {
        sealed_state = "unsealed";
        fprintf(stderr, "witnessd: device key released (%s)\n",
                release.have_key ? "boot state matches a signed release" : "boot state matches the provisioned state");
    } else if (release.have_key && !release.have_policy) {
        sealed_state = "locked";
        fprintf(stderr, "witnessd: device key locked until a signed release policy is delivered\n");
    } else {
        sealed_state = "locked"; /* fail closed whatever the reason */
        fprintf(stderr, "witnessd: device key LOCKED: boot state differs from %s (%s)\n",
                release.have_key ? "the signed release" : "provisioning", Tss2_RC_Decode(rc));
    }
}

static void hex(FILE *out, const uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
        fprintf(out, "%02x", data[i]);
}

static void json_string(FILE *out, const char *text)
{
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        if (*p == '"' || *p == '\\')
            fprintf(out, "\\%c", *p);
        else if (*p < 0x20)
            fprintf(out, "\\u%04x", *p);
        else
            fputc(*p, out);
    }
    fputc('"', out);
}

static int parse_nonce(const char *text, TPM2B_DATA *nonce)
{
    size_t length = strspn(text, "0123456789abcdefABCDEF");
    if (length < 16 || length % 2 || length / 2 > sizeof nonce->buffer)
        return -1;
    nonce->size = (UINT16)(length / 2);
    for (size_t i = 0; i < nonce->size; i++) {
        unsigned value;
        sscanf(text + 2 * i, "%2x", &value);
        nonce->buffer[i] = (uint8_t)value;
    }
    return 0;
}

static TSS2_RC read_pcrs(FILE *out)
{
    fprintf(out, "\"pcrs\":{");
    int first = 1;
    for (uint32_t base = 0; base < 10; base += 8) {
        uint32_t mask = QUOTE_PCR_MASK & (0xFFu << base);
        TPML_PCR_SELECTION selection, *selection_out = NULL;
        TPML_DIGEST *values = NULL;
        UINT32 update_counter;
        selection_from_mask(&selection, mask);
        TSS2_RC rc = Esys_PCR_Read(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &selection, &update_counter,
                                   &selection_out, &values);
        if (rc != TSS2_RC_SUCCESS)
            return rc;
        uint32_t index = 0;
        for (uint32_t pcr = base; pcr < base + 8 && pcr < 10 && index < values->count; pcr++) {
            if (!(mask & (1u << pcr)))
                continue;
            fprintf(out, "%s\"%u\":\"", first ? "" : ",", pcr);
            hex(out, values->digests[index].buffer, values->digests[index].size);
            fputc('"', out);
            first = 0;
            index++;
        }
        Esys_Free(selection_out);
        Esys_Free(values);
    }
    fprintf(out, "},");
    return TSS2_RC_SUCCESS;
}

static void answer(FILE *out, const char *request)
{
    TPM2B_DATA nonce;
    if (strncmp(request, "ATTEST ", 7) != 0 || parse_nonce(request + 7, &nonce) != 0) {
        fprintf(out, "{\"error\":\"expected: ATTEST <nonce, 16-128 hex chars>\"}\n");
        return;
    }
    TPMT_SIG_SCHEME scheme = {.scheme = TPM2_ALG_NULL}; /* use the AK's own ECDSA-SHA256 scheme */
    TPML_PCR_SELECTION selection;
    TPM2B_ATTEST *quoted = NULL;
    TPMT_SIGNATURE *signature = NULL;
    selection_from_mask(&selection, QUOTE_PCR_MASK);
    TSS2_RC rc = Esys_Quote(esys, attestation_key, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &nonce, &scheme,
                            &selection, &quoted, &signature);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(out, "{\"error\":");
        json_string(out, Tss2_RC_Decode(rc));
        fprintf(out, "}\n");
        return;
    }

    uint8_t buffer[sizeof(TPM2B_PUBLIC) + sizeof(TPMT_SIGNATURE)];
    size_t offset = 0;
    char hostname[64] = "qnx";
    gethostname(hostname, sizeof hostname - 1);

    fprintf(out, "{\"device\":");
    json_string(out, hostname);
    fprintf(out, ",\"ak_public\":\"");
    if (Tss2_MU_TPM2B_PUBLIC_Marshal(attestation_key_public, buffer, sizeof buffer, &offset) == TSS2_RC_SUCCESS)
        hex(out, buffer, offset);
    fprintf(out, "\",\"quote\":\"");
    hex(out, quoted->attestationData, quoted->size);
    fprintf(out, "\",\"signature\":\"");
    offset = 0;
    if (Tss2_MU_TPMT_SIGNATURE_Marshal(signature, buffer, sizeof buffer, &offset) == TSS2_RC_SUCCESS)
        hex(out, buffer, offset);
    fprintf(out, "\",");
    if (read_pcrs(out) != TSS2_RC_SUCCESS)
        fprintf(out, "\"pcrs_error\":true,");
    TPMT_SIGNATURE *device_signature = NULL;
    rc = device_key_sign(DEVICE_KEY_LABEL, nonce.buffer, nonce.size, &device_signature);
    /* the state of this request, not of start-up: a release policy may have arrived since */
    fprintf(out, "\"sealed\":");
    json_string(out, rc == TSS2_RC_SUCCESS ? "unsealed" : device_key == ESYS_TR_NONE ? sealed_state : "locked");
    if (rc == TSS2_RC_SUCCESS) {
        fprintf(out, ",\"device_key\":{\"public\":\"");
        offset = 0;
        if (Tss2_MU_TPM2B_PUBLIC_Marshal(&device_key_public, buffer, sizeof buffer, &offset) == TSS2_RC_SUCCESS)
            hex(out, buffer, offset);
        fprintf(out, "\",\"signature\":\"");
        offset = 0;
        if (Tss2_MU_TPMT_SIGNATURE_Marshal(device_signature, buffer, sizeof buffer, &offset) == TSS2_RC_SUCCESS)
            hex(out, buffer, offset);
        /* TPM2_Certify: the AK vouches that a key with exactly this public area lives in this TPM */
        TPM2B_ATTEST *certified = NULL;
        TPMT_SIGNATURE *certify_signature = NULL;
        if (Esys_Certify(esys, device_key, attestation_key, ESYS_TR_PASSWORD, ESYS_TR_PASSWORD, ESYS_TR_NONE, &nonce,
                         &scheme, &certified, &certify_signature) == TSS2_RC_SUCCESS) {
            fprintf(out, "\",\"certify\":\"");
            hex(out, certified->attestationData, certified->size);
            fprintf(out, "\",\"certify_signature\":\"");
            offset = 0;
            if (Tss2_MU_TPMT_SIGNATURE_Marshal(certify_signature, buffer, sizeof buffer, &offset) == TSS2_RC_SUCCESS)
                hex(out, buffer, offset);
        }
        Esys_Free(certified);
        Esys_Free(certify_signature);
        fprintf(out, "\"}");
    } else {
        fprintf(out, ",\"device_key_error\":");
        json_string(out, Tss2_RC_Decode(rc));
    }
    Esys_Free(device_signature);
    fprintf(out, ",\"eventlog\":[");
    FILE *log = fopen(eventlog_path, "r");
    char line[1200];
    int first = 1;
    while (log && fgets(line, sizeof line, log)) {
        line[strcspn(line, "\n")] = '\0';
        fputs(first ? "" : ",", out);
        json_string(out, line);
        first = 0;
    }
    if (log)
        fclose(log);
    fprintf(out, "]}\n");
    Esys_Free(quoted);
    Esys_Free(signature);
}

static uint64_t now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* One request line per connection, read without blocking anyone: up to MAX_PENDING clients are
 * read in parallel, each must send its line within REQUEST_BUDGET_MS, and the oldest is dropped
 * when the table is full. The watchdog covers only the TPM work and the reply, never a client. */
static void serve(int port)
{
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = INADDR_ANY};
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof address) != 0 || listen(listener, 128) != 0) {
        fprintf(stderr, "witnessd: cannot listen on port %d: %s\n", port, strerror(errno));
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "witnessd: listening on port %d\n", port);
    struct { int fd; size_t len; uint64_t deadline; char line[300]; } pending[MAX_PENDING];
    size_t count = 0;
    for (;;) {
        struct pollfd fds[MAX_PENDING + 1] = {{.fd = listener, .events = POLLIN}};
        uint64_t now = now_ms(), wake = now + 60000;
        for (size_t i = 0; i < count; i++) {
            fds[i + 1] = (struct pollfd){.fd = pending[i].fd, .events = POLLIN};
            wake = pending[i].deadline < wake ? pending[i].deadline : wake;
        }
        int nfds = (int)count + 1;
        if (poll(fds, nfds, wake > now ? (int)(wake - now) : 0) < 0 && errno != EINTR)
            continue;
        now = now_ms();
        /* clients first (indexes shift as entries are removed, so walk backwards) */
        for (size_t i = count; i-- > 0;) {
            int done = 0;
            if (fds[i + 1].revents) {
                ssize_t n = read(pending[i].fd, pending[i].line + pending[i].len, sizeof pending[i].line - 1 - pending[i].len);
                if (n <= 0) {
                    done = 1;
                } else {
                    pending[i].len += (size_t)n;
                    pending[i].line[pending[i].len] = '\0';
                    if (strchr(pending[i].line, '\n')) {
                        pthread_mutex_lock(&tpm_lock);
                        alarm(WATCHDOG_SECONDS); /* a hang in the TPM path ends this agent instance */
                        FILE *output = fdopen(pending[i].fd, "w");
                        if (output) {
                            answer(output, pending[i].line);
                            fclose(output);
                            pending[i].fd = -1;
                        }
                        alarm(0);
                        pthread_mutex_unlock(&tpm_lock);
                        done = 1;
                    } else if (pending[i].len == sizeof pending[i].line - 1) {
                        done = 1; /* no newline in a full buffer: not our protocol */
                    }
                }
            } else if (now >= pending[i].deadline) {
                done = 1;
            }
            if (done) {
                if (pending[i].fd >= 0)
                    close(pending[i].fd);
                pending[i] = pending[--count];
            }
        }
        if (fds[0].revents & POLLIN) {
            int client = accept(listener, NULL, NULL);
            if (client < 0)
                continue;
            int buffer = 256 * 1024; /* the whole reply fits: a client that never reads cannot block the write */
            struct timeval timeout = {.tv_sec = 1};
            setsockopt(client, SOL_SOCKET, SO_SNDBUF, &buffer, sizeof buffer);
            setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
            if (count == MAX_PENDING) { /* full: drop the oldest */
                size_t oldest = 0;
                for (size_t i = 1; i < count; i++)
                    oldest = pending[i].deadline < pending[oldest].deadline ? i : oldest;
                close(pending[oldest].fd);
                pending[oldest] = pending[--count];
            }
            pending[count].fd = client;
            pending[count].len = 0;
            pending[count].line[0] = '\0';
            pending[count++].deadline = now + REQUEST_BUDGET_MS;
        }
    }
}

/* Local signing channel for fleet reports (witness-report.h): QNX message passing, so the security policy decides
 * which process types may connect; the TCP port never signs caller data. */
static void *report_channel(void *unused)
{
    (void)unused;
    name_attach_t *attach = name_attach(NULL, REPORT_CHANNEL, 0);
    if (attach == NULL) {
        fprintf(stderr, "witnessd: no report channel: name_attach: %s\n", strerror(errno));
        return NULL;
    }
    for (;;) {
        union { struct _pulse pulse; uint16_t type; struct report_request request; } msg;
        struct _msg_info info;
        int rcvid = MsgReceive(attach->chid, &msg, sizeof msg, &info);
        if (rcvid == -1)
            continue;
        if (rcvid == 0) { /* pulse: a client went away */
            if (msg.pulse.code == _PULSE_CODE_DISCONNECT)
                ConnectDetach(msg.pulse.scoid);
            continue;
        }
        if (msg.type == _IO_CONNECT) { /* name_open() */
            MsgReply(rcvid, EOK, NULL, 0);
            continue;
        }
        /* sign only bytes the sender sent: size must fit what actually arrived, never stale stack */
        if (msg.type != REPORT_MSG || msg.request.size > REPORT_MAX ||
            info.srcmsglen < (ssize_t)(offsetof(struct report_request, report) + msg.request.size)) {
            MsgError(rcvid, msg.type == REPORT_MSG ? EMSGSIZE : ENOSYS);
            continue;
        }
        struct report_reply reply = {0};
        TPMT_SIGNATURE *signature = NULL;
        pthread_mutex_lock(&tpm_lock);
        alarm(WATCHDOG_SECONDS);
        TSS2_RC rc = device_key_sign(REPORT_LABEL, (const uint8_t *)msg.request.report, msg.request.size, &signature);
        alarm(0);
        pthread_mutex_unlock(&tpm_lock);
        reply.rc = rc;
        if (rc == TSS2_RC_SUCCESS && signature->sigAlg == TPM2_ALG_ECDSA) {
            TPMS_SIGNATURE_ECC *ecc = &signature->signature.ecdsa;
            reply.r_size = ecc->signatureR.size <= 32 ? ecc->signatureR.size : 0;
            reply.s_size = ecc->signatureS.size <= 32 ? ecc->signatureS.size : 0;
            memcpy(reply.r, ecc->signatureR.buffer, reply.r_size);
            memcpy(reply.s, ecc->signatureS.buffer, reply.s_size);
        }
        Esys_Free(signature);
        MsgReply(rcvid, EOK, &reply, sizeof reply);
    }
}

/* Raw TPM2 command through the TCTI (before ESYS exists). Returns the response size, or 0. */
static size_t raw_command(TSS2_TCTI_CONTEXT *tcti, const uint8_t *cmd, size_t len, uint8_t *resp, size_t max)
{
    size_t size = max;
    if (Tss2_Tcti_Transmit(tcti, len, cmd) != TSS2_RC_SUCCESS ||
        Tss2_Tcti_Receive(tcti, &size, resp, TSS2_TCTI_TIMEOUT_BLOCK) != TSS2_RC_SUCCESS || size < 10)
        return 0;
    return size;
}

/* witnessd is the only TPM client after boot and talks to the driver directly, so objects and sessions
 * left loaded by a previous instance (killed by the watchdog) are flushed before starting. */
static void flush_stale_handles(TSS2_TCTI_CONTEXT *tcti)
{
    static const uint32_t ranges[] = {0x80000000, 0x02000000, 0x03000000}; /* transient, HMAC/policy sessions */
    for (size_t r = 0; r < sizeof ranges / sizeof *ranges; r++) {
        uint8_t cmd[22] = {0x80, 0x01, 0, 0, 0, 22, 0, 0, 0x01, 0x7A, 0, 0, 0, 1}; /* GetCapability(HANDLES) */
        uint8_t resp[512];
        cmd[14] = ranges[r] >> 24;
        cmd[21] = 64; /* propertyCount */
        size_t size = raw_command(tcti, cmd, sizeof cmd, resp, sizeof resp);
        if (size < 19)
            continue;
        uint32_t count = (uint32_t)resp[15] << 24 | resp[16] << 16 | resp[17] << 8 | resp[18];
        for (uint32_t i = 0; i < count && 19 + 4 * (i + 1) <= size; i++) {
            uint8_t flush[14] = {0x80, 0x01, 0, 0, 0, 14, 0, 0, 0x01, 0x65}; /* FlushContext */
            memcpy(flush + 10, resp + 19 + 4 * i, 4);
            uint8_t reply[16];
            raw_command(tcti, flush, sizeof flush, reply, sizeof reply);
        }
        if (count)
            fprintf(stderr, "witnessd: flushed %u stale TPM handle(s)\n", count);
    }
}

static void watchdog_expired(int signo)
{
    (void)signo;
    static const char message[] = "witnessd: watchdog: request took too long, restarting\n";
    write(STDERR_FILENO, message, sizeof message - 1);
    _exit(70);
}

static int run_agent(int port, const char *tpm_device)
{
    TSS2_TCTI_CONTEXT *tcti = NULL;
    alarm(WATCHDOG_SECONDS * 3); /* start-up, including provisioning */
    /* The TCTI is linked in, not loaded: a restarted child must run only code mapped at the measured launch,
     * never a library root could replace in /system/lib since boot. */
    size_t size = 0;
    TSS2_RC rc = Tss2_Tcti_Witness_Init(NULL, &size, tpm_device);
    if (rc == TSS2_RC_SUCCESS && (tcti = calloc(1, size)) == NULL)
        rc = TSS2_TCTI_RC_MEMORY;
    if (rc == TSS2_RC_SUCCESS)
        rc = Tss2_Tcti_Witness_Init(tcti, &size, tpm_device);
    if (rc == TSS2_RC_SUCCESS) {
        flush_stale_handles(tcti);
        rc = Esys_Initialize(&esys, tcti, NULL);
    }
    if (rc != TSS2_RC_SUCCESS) {
        fail("TPM stack", rc);
        return EXIT_FAILURE;
    }
    if ((rc = create_attestation_key()) != TSS2_RC_SUCCESS) {
        fail("attestation key", rc);
        return EXIT_FAILURE;
    }
    provision_or_load();
    alarm(0);
    pthread_t reporter;
    if (pthread_create(&reporter, NULL, report_channel, NULL) != 0)
        fprintf(stderr, "witnessd: no report channel thread\n");
    serve(port);
    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    int port = DEFAULT_PORT, opt, foreground = 0;
    const char *tpm_device = "/dev/tpm0";
    while ((opt = getopt(argc, argv, "p:l:s:t:f")) != -1) {
        switch (opt) {
        case 'p': port = atoi(optarg); break;
        case 'l': eventlog_path = optarg; break;
        case 's': state_dir = optarg; break;
        case 't': tpm_device = optarg; break;
        case 'f': foreground = 1; break;
        default:
            fprintf(stderr, "usage: witnessd [-p port] [-l eventlog] [-s state-dir] [-t tpm-device] [-f]\n");
            return 2;
        }
    }
    /* below the default 10: attestation never preempts normal-priority work, and the driver serves it at this priority */
    struct sched_param param = {.sched_priority = AGENT_PRIORITY};
    if (pthread_setschedparam(pthread_self(), SCHED_RR, &param) != 0)
        fprintf(stderr, "witnessd: cannot lower priority to %d\n", AGENT_PRIORITY);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGALRM, watchdog_expired);
    /* OpenSSL (under ESYS) initialised once, before any fork and without openssl.cnf: a restarted agent inherits
     * it and reads no config file or provider module later. Defence in depth: OPENSSLDIR is on the read-only IFS. */
    if (!OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL))
        fprintf(stderr, "witnessd: OpenSSL initialisation failed\n");
    if (!foreground && fork() > 0)
        return EXIT_SUCCESS;

    /* Supervisor: the agent runs in a child; if the watchdog or a crash ends it, start a fresh one. */
    for (unsigned restarts = 0;; restarts++) {
        time_t started = time(NULL);
        pid_t child = fork();
        if (child == 0)
            return run_agent(port, tpm_device);
        int status = 0;
        if (child < 0 || waitpid(child, &status, 0) < 0)
            return EXIT_FAILURE;
        if (time(NULL) - started > 300) /* ran healthy for 5 min: back to fast restarts */
            restarts = 0;
        fprintf(stderr, "witnessd: agent exited (status 0x%x), restart %u\n", status, restarts + 1);
        sleep(restarts < 5 ? 1 : 10);
    }
}
