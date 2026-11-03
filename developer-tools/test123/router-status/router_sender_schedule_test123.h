/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef TEST123_ROUTER_SENDER_SCHEDULE_H
#define TEST123_ROUTER_SENDER_SCHEDULE_H

#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <poll.h>

enum send_window_gate {
    SEND_WINDOW_CLOCK_ERROR = -1,
    SEND_WINDOW_EXPIRED = 0,
    SEND_WINDOW_WAIT = 1,
    SEND_WINDOW_READY = 2
};

static inline enum send_window_gate send_window_gate(uint64_t now,
                                                     uint64_t due,
                                                     uint64_t deadline) {
    if (!now) return SEND_WINDOW_CLOCK_ERROR;
    if (now >= deadline) return SEND_WINDOW_EXPIRED;
    return now < due ? SEND_WINDOW_WAIT : SEND_WINDOW_READY;
}

/* Recompute the poll timeout from an absolute deadline after every EINTR. */
static inline int sender_poll_timeout_ms(uint64_t now, uint64_t deadline) {
    if (!now) return -1;
    if (now >= deadline) return 0;
    const uint64_t left = deadline - now;
    const uint64_t rounded_ms = (left + UINT64_C(999999)) / UINT64_C(1000000);
    return rounded_ms > (uint64_t)INT_MAX ? INT_MAX : (int)rounded_ms;
}

typedef uint64_t (*sender_clock_fn)(void *context);
typedef int (*sender_poll_fn)(struct pollfd *fds, nfds_t count, int timeout_ms,
                              void *context);

/* Retry EINTR only after recomputing time against the same absolute deadline.
 * A rounded poll timeout is also retried until the clock reaches the deadline. */
static inline int sender_poll_until_deadline(struct pollfd *fds,
                                             uint64_t deadline,
                                             sender_clock_fn clock_fn,
                                             sender_poll_fn poll_fn,
                                             void *context) {
    for (;;) {
        const int timeout = sender_poll_timeout_ms(clock_fn(context), deadline);
        if (timeout < 0) return -2;
        if (timeout == 0) return 0;
        fds->revents = 0;
        const int result = poll_fn(fds, 1, timeout, context);
        if (result < 0 && errno == EINTR) continue;
        if (result == 0) continue;
        return result;
    }
}

#endif
