/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include "router_sender_schedule_test123.h"

#define NS_PER_MS 1000000ULL

struct fake_poll_context {
    uint64_t now;
    unsigned calls;
    int timeouts[4];
};

static uint64_t fake_clock(void *opaque) {
    return ((struct fake_poll_context *)opaque)->now;
}

static int fake_poll(struct pollfd *fds, nfds_t count, int timeout_ms,
                     void *opaque) {
    (void)fds;
    (void)count;
    struct fake_poll_context *context = opaque;
    if (context->calls >= 4) return -1;
    context->timeouts[context->calls] = timeout_ms;
    context->calls++;
    if (context->calls <= 2) {
        context->now += 9ULL * NS_PER_MS;
        errno = EINTR;
        return -1;
    }
    context->now += (uint64_t)timeout_ms * NS_PER_MS;
    return 0;
}

int main(void) {
    const uint64_t start = 1000000000ULL;
    const uint64_t deadline = start + 40ULL * NS_PER_MS;
    unsigned sends = 0;
    unsigned simulated_receives = 0;

    if (send_window_gate(start, start, deadline) != SEND_WINDOW_READY) return 1;
    ++sends;
    const uint64_t second_due = start + 10ULL * NS_PER_MS;
    if (send_window_gate(second_due, second_due, deadline) != SEND_WINDOW_READY) return 2;
    ++sends;

    /* A burst of receive work advances monotonic time beyond the third-send
     * slot. The real sender must re-check the same gate before every send. */
    const uint64_t third_due = second_due + 10ULL * NS_PER_MS;
    uint64_t now = third_due - NS_PER_MS;
    for (unsigned i = 0; i < 9; ++i) {
        ++simulated_receives;
        now += 5ULL * NS_PER_MS;
        if (send_window_gate(now, third_due, deadline) == SEND_WINDOW_EXPIRED) break;
    }
    if (simulated_receives < 5 || now < deadline ||
        send_window_gate(now, third_due, deadline) != SEND_WINDOW_EXPIRED || sends != 2) return 3;

    if (send_window_gate(0, start, deadline) != SEND_WINDOW_CLOCK_ERROR) return 4;
    const uint64_t poll_deadline = start + 25ULL * NS_PER_MS;
    struct fake_poll_context context = {.now = start};
    struct pollfd fake_fd = {.fd = 17, .events = POLLIN};
    const int poll_result = sender_poll_until_deadline(
        &fake_fd, poll_deadline, fake_clock, fake_poll, &context);
    if (poll_result != 0 || context.calls != 3 || context.now < poll_deadline ||
        context.timeouts[0] != 25 || context.timeouts[1] != 16 ||
        context.timeouts[2] != 7) return 5;
    if (sender_poll_timeout_ms(0, poll_deadline) != -1) return 6;
    puts("PASS Test123 schedule gate, receive-budget exhaustion, and no-packet EINTR deadline exit");
    return 0;
}
