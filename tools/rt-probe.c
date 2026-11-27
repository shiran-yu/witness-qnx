/* SPDX-License-Identifier: Apache-2.0
 * rt-probe: a periodic real-time loop that reports its period jitter (how far each period is from 1/hz).
 * Usage: rt-probe [-p priority] [-f hz] [-s seconds]
 * SCHED_FIFO at `priority`, absolute wake-ups every 1/hz s on CLOCK_MONOTONIC; prints the jitter
 * distribution in microseconds. Not part of the image: copied to a device for the latency test
 * (docs/evidence/latency.log). */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define BUCKETS 10001 /* 1 us each; the last one holds everything >= 10 ms */

static uint64_t ns(const struct timespec *t)
{
    return (uint64_t)t->tv_sec * 1000000000u + (uint64_t)t->tv_nsec;
}

static unsigned percentile(const uint64_t *histogram, uint64_t total, double fraction)
{
    uint64_t want = (uint64_t)(fraction * (double)total), seen = 0;
    for (unsigned us = 0; us < BUCKETS; us++)
        if ((seen += histogram[us]) > want)
            return us;
    return BUCKETS - 1;
}

int main(int argc, char **argv)
{
    int priority = 10, hz = 1000, seconds = 30, opt;
    while ((opt = getopt(argc, argv, "p:f:s:")) != -1) {
        switch (opt) {
        case 'p': priority = atoi(optarg); break;
        case 'f': hz = atoi(optarg); break;
        case 's': seconds = atoi(optarg); break;
        default:
            fprintf(stderr, "usage: rt-probe [-p priority] [-f hz] [-s seconds]\n");
            return 2;
        }
    }
    if (hz < 1 || hz > 10000 || seconds < 1 || seconds > 3600) {
        fprintf(stderr, "rt-probe: hz 1-10000, seconds 1-3600\n");
        return 2;
    }
    struct sched_param param = {.sched_priority = priority};
    int rc = pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
    if (rc != 0) {
        fprintf(stderr, "rt-probe: cannot run at SCHED_FIFO %d: %s\n", priority, strerror(rc));
        return 1;
    }
    static uint64_t histogram[BUCKETS];
    uint64_t period = 1000000000u / (uint64_t)hz, total = (uint64_t)hz * (uint64_t)seconds, worst = 0, sum = 0;
    struct timespec next, now;
    clock_gettime(CLOCK_MONOTONIC, &next);
    uint64_t previous = ns(&next);
    for (uint64_t i = 0; i <= total; i++) { /* wake-up 0 only sets `previous`: `total` periods measured */
        uint64_t due = ns(&next) + period;
        next.tv_sec = (time_t)(due / 1000000000u);
        next.tv_nsec = (long)(due % 1000000000u);
        while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, NULL) == EINTR)
            ;
        clock_gettime(CLOCK_MONOTONIC, &now);
        /* jitter: how far this period was from 1/hz (absolute lateness carries a constant clock-tick offset) */
        uint64_t interval = ns(&now) - previous, late = interval > period ? interval - period : period - interval;
        previous = ns(&now);
        if (i == 0)
            continue;
        histogram[late / 1000 < BUCKETS - 1 ? late / 1000 : BUCKETS - 1]++;
        sum += late;
        if (late > worst)
            worst = late;
    }
    uint64_t over_1ms = 0;
    for (unsigned us = 1000; us < BUCKETS; us++)
        over_1ms += histogram[us];
    printf("rt-probe: priority %d, %d Hz, %llu wake-ups: jitter us p50 %u p99 %u p99.9 %u max %llu mean %.1f;"
           " over 1 ms: %llu\n",
           priority, hz, (unsigned long long)total, percentile(histogram, total, 0.5),
           percentile(histogram, total, 0.99), percentile(histogram, total, 0.999),
           (unsigned long long)(worst / 1000), (double)sum / (double)total / 1000.0,
           (unsigned long long)over_1ms);
    return 0;
}
