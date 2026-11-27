/* SPDX-License-Identifier: Apache-2.0 */
/* witnessd: remote-attestation agent for QNX 8.0, built on QNX's own TSS2 ESYS stack.
 *
 * Path: witnessd -> ESYS -> tctildr default (libtcti_tabrm) -> tabrm /dev/tpmrm0
 *       -> libtss2-tcti-witness -> dev-tpm-tis /dev/tpm0 -> TPM
 *
 * On start it derives the attestation key (AK: ECC P-256, restricted signing, from the endorsement
 * hierarchy, so the same key comes back on every boot of the same TPM) and loads the device key: an
 * ECC P-256 signing key whose only authorisation is PolicyPCR over PCR 0,2,4,5,7,8,9 (firmware, boot
 * image, disk, system partition, applications). The TPM lets it sign only in the provisioned boot
 * state, so a signature with it over the verifier's nonce proves that state, and a fleet service can
 * use it as the device's credential. If no device key exists yet (first boot in the factory), it
 * creates one.
 *
 * Protocol (TCP, one request per connection):  "ATTEST <nonce-hex>\n"  ->  one JSON object
 *   ak_public  TPM2B_PUBLIC (hex)     quote      TPMS_ATTEST (hex)    signature  TPMT_SIGNATURE (hex)
 *   pcrs       PCR 0-9 (sha256, hex)  eventlog   Witness event log    sealed     unsealed|locked|error
 *   device_key {public, signature over SHA256("witness:device-key:" nonce)} or device_key_error */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

#define DEFAULT_PORT 7650
#define QUOTE_PCR_MASK 0x0003FF /* PCR 0-9 */
#define SEAL_PCR_MASK 0x0003B5  /* PCR 0,2,4,5,7 (firmware, boot image, disk, Secure Boot), 8 (system), 9 (apps) */
#define DEVICE_KEY_LABEL "witness:device-key:"

static ESYS_CONTEXT *esys;
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
static TSS2_RC pcr_policy_session(TPM2_SE session_type, ESYS_TR *session)
{
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_NULL};
    TSS2_RC rc = Esys_StartAuthSession(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                       NULL, session_type, &symmetric, TPM2_ALG_SHA256, session);
    if (rc != TSS2_RC_SUCCESS)
        return rc;
    TPM2B_DIGEST current_values = {0}; /* empty: the TPM uses the PCRs as they are now */
    TPML_PCR_SELECTION selection;
    selection_from_mask(&selection, SEAL_PCR_MASK);
    rc = Esys_PolicyPCR(esys, *session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &current_values, &selection);
    if (rc != TSS2_RC_SUCCESS)
        Esys_FlushContext(esys, *session);
    return rc;
}

static int write_blob(const char *path, const uint8_t *data, size_t size)
{
    char tmp[256];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return -1;
    int ok = write(fd, data, size) == (ssize_t)size;
    ok = (fsync(fd) == 0) && ok;
    close(fd);
    return ok && rename(tmp, path) == 0 ? 0 : -1;
}

/* First boot: a P-256 signing key, created inside the TPM, usable only through PolicyPCR over SEAL_PCR_MASK. */
static TSS2_RC create_device_key(ESYS_TR storage_key, const char *blob_path)
{
    ESYS_TR trial;
    TPM2B_DIGEST *policy = NULL;
    TPM2B_PRIVATE *sealed_private = NULL;
    TPM2B_PUBLIC *sealed_public = NULL;
    TSS2_RC rc = pcr_policy_session(TPM2_SE_TRIAL, &trial);
    if (rc != TSS2_RC_SUCCESS)
        return rc;
    rc = Esys_PolicyGetDigest(esys, trial, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &policy);
    Esys_FlushContext(esys, trial);
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

/* Sign SHA256(DEVICE_KEY_LABEL || data) with the device key; the TPM refuses unless the PCR policy holds. */
static TSS2_RC device_key_sign(const uint8_t *data, size_t size, TPMT_SIGNATURE **signature)
{
    uint8_t message[sizeof DEVICE_KEY_LABEL - 1 + sizeof(TPM2B_DATA)];
    TPM2B_MAX_BUFFER buffer = {.size = (UINT16)(sizeof DEVICE_KEY_LABEL - 1 + size)};
    TPM2B_DIGEST *digest = NULL;
    TPMT_TK_HASHCHECK *ticket = NULL;
    if (device_key == ESYS_TR_NONE || size > sizeof(TPM2B_DATA))
        return TSS2_ESYS_RC_BAD_VALUE;
    memcpy(message, DEVICE_KEY_LABEL, sizeof DEVICE_KEY_LABEL - 1);
    memcpy(message + sizeof DEVICE_KEY_LABEL - 1, data, size);
    memcpy(buffer.buffer, message, buffer.size);
    TSS2_RC rc = Esys_Hash(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &buffer, TPM2_ALG_SHA256, ESYS_TR_RH_NULL,
                           &digest, &ticket);
    if (rc != TSS2_RC_SUCCESS)
        return rc;
    ESYS_TR session;
    rc = pcr_policy_session(TPM2_SE_POLICY, &session);
    if (rc == TSS2_RC_SUCCESS) {
        TPMT_SIG_SCHEME scheme = {.scheme = TPM2_ALG_NULL}; /* the key's own ECDSA-SHA256 */
        rc = Esys_Sign(esys, device_key, session, ESYS_TR_NONE, ESYS_TR_NONE, digest, &scheme, ticket, signature);
        Esys_FlushContext(esys, session);
    }
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
            fprintf(stderr, "witnessd: provisioned: device key bound to PCR 0,2,4,5,7,8,9\n");
    }
    rc = load_device_key(storage_key, blob_path);
    Esys_FlushContext(esys, storage_key);
    TPMT_SIGNATURE *probe = NULL;
    if (rc == TSS2_RC_SUCCESS)
        rc = device_key_sign((const uint8_t *)"boot", 4, &probe);
    Esys_Free(probe);
    if (rc == TSS2_RC_SUCCESS) {
        sealed_state = "unsealed";
        fprintf(stderr, "witnessd: device key released (boot state matches the provisioned state)\n");
    } else {
        sealed_state = "locked"; /* fail closed whatever the reason */
        fprintf(stderr, "witnessd: device key LOCKED: boot state differs from provisioning (%s)\n",
                Tss2_RC_Decode(rc));
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
    fprintf(out, "\"sealed\":");
    json_string(out, sealed_state);
    TPMT_SIGNATURE *device_signature = NULL;
    rc = device_key_sign(nonce.buffer, nonce.size, &device_signature);
    if (rc == TSS2_RC_SUCCESS) {
        fprintf(out, ",\"device_key\":{\"public\":\"");
        offset = 0;
        if (Tss2_MU_TPM2B_PUBLIC_Marshal(&device_key_public, buffer, sizeof buffer, &offset) == TSS2_RC_SUCCESS)
            hex(out, buffer, offset);
        fprintf(out, "\",\"signature\":\"");
        offset = 0;
        if (Tss2_MU_TPMT_SIGNATURE_Marshal(device_signature, buffer, sizeof buffer, &offset) == TSS2_RC_SUCCESS)
            hex(out, buffer, offset);
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

static void serve(int port)
{
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = INADDR_ANY};
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof address) != 0 || listen(listener, 4) != 0) {
        fprintf(stderr, "witnessd: cannot listen on port %d: %s\n", port, strerror(errno));
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "witnessd: listening on port %d\n", port);
    for (;;) {
        int client = accept(listener, NULL, NULL);
        if (client < 0)
            continue;
        struct timeval timeout = {.tv_sec = 1}; /* one slow client must not stall the next */
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
        /* separate streams: C forbids switching one stream from reading to writing without a seek */
        FILE *input = fdopen(client, "r");
        FILE *output = fdopen(dup(client), "w");
        char request[300];
        if (input && output && fgets(request, sizeof request, input))
            answer(output, request);
        if (output)
            fclose(output);
        if (input)
            fclose(input);
        else
            close(client);
    }
}

int main(int argc, char **argv)
{
    int port = DEFAULT_PORT, opt, foreground = 0;
    while ((opt = getopt(argc, argv, "p:l:s:f")) != -1) {
        switch (opt) {
        case 'p': port = atoi(optarg); break;
        case 'l': eventlog_path = optarg; break;
        case 's': state_dir = optarg; break;
        case 'f': foreground = 1; break;
        default:
            fprintf(stderr, "usage: witnessd [-p port] [-l eventlog] [-s state-dir] [-f]\n");
            return 2;
        }
    }
    signal(SIGPIPE, SIG_IGN);

    TSS2_TCTI_CONTEXT *tcti = NULL;
    TSS2_RC rc = Tss2_TctiLdr_Initialize(NULL, &tcti); /* QNX default: tabrm (/dev/tpmrm0) */
    if (rc == TSS2_RC_SUCCESS)
        rc = Esys_Initialize(&esys, tcti, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fail("TPM stack", rc);
        return EXIT_FAILURE;
    }
    if ((rc = create_attestation_key()) != TSS2_RC_SUCCESS) {
        fail("attestation key", rc);
        return EXIT_FAILURE;
    }
    provision_or_load();
    if (!foreground && fork() > 0)
        return EXIT_SUCCESS;
    serve(port);
    return EXIT_SUCCESS;
}
