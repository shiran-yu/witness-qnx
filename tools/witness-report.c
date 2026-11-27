/* SPDX-License-Identifier: Apache-2.0 */
/* witness-report: a device application that sends signed status reports to the fleet service.
 *
 * Every interval: fetch a one-time challenge from the fleet service (GET /api/report/challenge), build a report
 * {"device","nonce","seq","uptime_s"}, have witnessd sign it with the TPM-bound device key over its local QNX
 * channel (witness-report.h), and POST report and signature to /api/report. On a tampered or rolled-back device
 * the TPM refuses the key, so the report goes out unsigned and the fleet service rejects it.
 * Runs under its own security type (witness_report_t), the only one allowed to connect to witnessd's channel.
 *
 *   witness-report [-s host:port] [-i seconds] [-1] [-f]     -1: one report, print the service's answer */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/neutrino.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "../agent/witness-report.h"

/* One HTTP/1.0 request; the response body (after the blank line) goes to body. Returns the status code or -1. */
static int http(const char *server, const char *method, const char *path, const char *payload, char *body, size_t max)
{
    char host[64];
    int port = 8650;
    if (sscanf(server, "%63[^:]:%d", host, &port) < 1)
        return -1;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, host, &address.sin_addr) != 1)
        return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval timeout = {.tv_sec = 5};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
    if (fd < 0 || connect(fd, (struct sockaddr *)&address, sizeof address) != 0) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    char request[2048];
    int n = snprintf(request, sizeof request,
                     "%s %s HTTP/1.0\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s",
                     method, path, host, payload ? strlen(payload) : 0, payload ? payload : "");
    if (n < 0 || (size_t)n >= sizeof request || write(fd, request, (size_t)n) != n) {
        close(fd);
        return -1;
    }
    char response[4096];
    size_t got = 0;
    ssize_t r;
    while (got < sizeof response - 1 && (r = read(fd, response + got, sizeof response - 1 - got)) > 0)
        got += (size_t)r;
    close(fd);
    response[got] = '\0';
    int status = -1;
    sscanf(response, "HTTP/%*s %d", &status);
    const char *start = strstr(response, "\r\n\r\n");
    snprintf(body, max, "%s", start ? start + 4 : "");
    return status;
}

static void to_hex(char *out, const uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
        sprintf(out + 2 * i, "%02x", data[i]);
    out[2 * size] = '\0';
}

/* One report. Returns 0 when the fleet service accepted it. */
static int report_once(const char *server, unsigned seq, int verbose)
{
    char body[1024], nonce[129] = "";
    int coid = name_open(REPORT_CHANNEL, 0); /* first: the security policy decides here, service or not */
    if (coid == -1 && verbose)
        fprintf(stderr, "witness-report: no channel to witnessd: %s\n", strerror(errno));
    int channel_errno = errno;
    if (http(server, "GET", "/api/report/challenge", NULL, body, sizeof body) != 200 ||
        sscanf(body, "{\"nonce\": \"%128[0-9a-f]\"", nonce) != 1) {
        if (verbose)
            fprintf(stderr, "witness-report: no challenge from %s\n", server);
        if (coid != -1)
            name_close(coid);
        return -1;
    }
    char hostname[64] = "unknown";
    gethostname(hostname, sizeof hostname - 1);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    struct report_request request = {.type = REPORT_MSG};
    int n = snprintf(request.report, sizeof request.report,
                     "{\"device\":\"%s\",\"nonce\":\"%s\",\"seq\":%u,\"uptime_s\":%ld}", hostname, nonce, seq,
                     (long)now.tv_sec);
    request.size = (uint16_t)n;

    struct report_reply reply = {.rc = 1};
    const char *error = NULL;
    char error_text[96];
    if (coid == -1) {
        snprintf(error_text, sizeof error_text, "no channel to witnessd: %s", strerror(channel_errno));
        error = error_text;
    } else {
        if (MsgSend(coid, &request, sizeof request, &reply, sizeof reply) == -1) {
            snprintf(error_text, sizeof error_text, "witnessd: %s", strerror(errno));
            error = error_text;
        } else if (reply.rc != 0 || reply.r_size == 0 || reply.s_size == 0) {
            snprintf(error_text, sizeof error_text, "device key refused by the TPM (rc 0x%x)", (unsigned)reply.rc);
            error = error_text;
        }
        name_close(coid);
    }

    /* the report is JSON without quotes needing escape except its own: send it as a string, escaped */
    char escaped[2 * REPORT_MAX], payload[3 * REPORT_MAX], r[65], s[65];
    size_t e = 0;
    for (int i = 0; i < n && e < sizeof escaped - 2; i++) {
        if (request.report[i] == '"' || request.report[i] == '\\')
            escaped[e++] = '\\';
        escaped[e++] = request.report[i];
    }
    escaped[e] = '\0';
    if (error) {
        snprintf(payload, sizeof payload, "{\"report\":\"%s\",\"error\":\"%s\"}", escaped, error);
    } else {
        to_hex(r, reply.r, reply.r_size);
        to_hex(s, reply.s, reply.s_size);
        snprintf(payload, sizeof payload, "{\"report\":\"%s\",\"r\":\"%s\",\"s\":\"%s\"}", escaped, r, s);
    }
    int status = http(server, "POST", "/api/report", payload, body, sizeof body);
    if (verbose)
        printf("report %u %s -> HTTP %d %s\n", seq, error ? error : "signed by the device key", status, body);
    return status == 200 ? 0 : -1;
}

int main(int argc, char **argv)
{
    const char *server = "10.0.2.2:8650"; /* the host, under QEMU user networking */
    int interval = 10, once = 0, foreground = 0, opt;
    while ((opt = getopt(argc, argv, "s:i:1f")) != -1) {
        switch (opt) {
        case 's': server = optarg; break;
        case 'i': interval = atoi(optarg) > 0 ? atoi(optarg) : 10; break;
        case '1': once = 1; break;
        case 'f': foreground = 1; break;
        default:
            fprintf(stderr, "usage: witness-report [-s host:port] [-i seconds] [-1] [-f]\n");
            return 2;
        }
    }
    if (once)
        return report_once(server, 1, 1) == 0 ? 0 : 1;
    if (!foreground && fork() > 0)
        return 0;
    for (unsigned seq = 1;; seq++) {
        report_once(server, seq, 0);
        sleep((unsigned)interval);
    }
}
