/* SPDX-License-Identifier: GPL-2.0-only */
#include "awdl_directed_responder_test105.h"
#include <errno.h>
#include <string.h>

int t105_nonce_is_usable(const uint8_t nonce[T105_NONCE_BYTES])
{
    static const uint8_t old_marker[8] = {'T','0','8','6','R','X','0','1'};
    size_t i;
    int zero = 1;
    if (nonce == NULL) return 0;
    for (i = 0; i < T105_NONCE_BYTES; ++i) {
        if (nonce[i] != 0) zero = 0;
    }
    return !zero && memcmp(nonce, old_marker, 8) != 0;
}

int t105_datagram_matches(const T105Datagram *d, const T105Expected *e)
{
    if (d == NULL || e == NULL || e->ifindex == 0 || !t105_nonce_is_usable(e->nonce))
        return 0;
    return d->payload_length == T105_NONCE_BYTES && !d->payload_truncated &&
        !d->control_truncated && d->pktinfo_present && d->hop_limit_present &&
        d->ifindex == e->ifindex && d->source_scope_id == e->ifindex &&
        d->hop_limit == 1 &&
        d->source_port == T105_REQUEST_PORT && d->destination_port == T105_REPLY_PORT &&
        memcmp(d->source_ipv6, e->peer_ipv6, 16) == 0 &&
        memcmp(d->destination_ipv6, e->local_ipv6, 16) == 0 &&
        memcmp(d->payload, e->nonce, T105_NONCE_BYTES) == 0;
}

T105Status t105_reply_once(const T105Io *io, void *ctx, const T105Expected *e,
                           T105Session *session, int timeout_ms, T105Stats *stats)
{
    int64_t now, previous_now, deadline;
    if (stats != NULL) memset(stats, 0, sizeof(*stats));
    if (io == NULL || io->wait_readable == NULL || io->receive == NULL ||
        io->send_reply == NULL || io->monotonic_ms == NULL || e == NULL ||
        session == NULL || stats == NULL || !session->armed || e->ifindex == 0 ||
        !t105_nonce_is_usable(e->nonce) || timeout_ms < 1 || timeout_ms > 60000)
        return T105_UNARMED;
    if (session->attempted) return T105_ALREADY_USED;
    session->attempted = 1;
    now = io->monotonic_ms(ctx);
    if (now < 0 || now > INT64_MAX - timeout_ms) {
        stats->receive_errno = EIO;
        return T105_RECEIVE_FAILED;
    }
    previous_now = now;
    deadline = now + timeout_ms;

    while (stats->datagrams_seen < T105_MAX_DATAGRAMS) {
        T105Datagram d;
        int error_number = 0, ready;
        int64_t remaining;
        ssize_t received;
        now = io->monotonic_ms(ctx);
        if (now < 0) { stats->receive_errno = EIO; return T105_RECEIVE_FAILED; }
        if (now < previous_now) {
            stats->receive_errno = ERANGE;
            return T105_RECEIVE_FAILED;
        }
        previous_now = now;
        remaining = deadline - now;
        if (remaining <= 0) return T105_TIMED_OUT;
        ready = io->wait_readable(ctx, (int)remaining);
        if (ready == 0) return T105_TIMED_OUT;
        if (ready < 0) { stats->receive_errno = errno; return T105_RECEIVE_FAILED; }
        memset(&d, 0, sizeof(d));
        received = io->receive(ctx, &d, &error_number);
        if (received < 0) {
            if (error_number == EAGAIN || error_number == EWOULDBLOCK || error_number == EINTR)
                continue;
            stats->receive_errno = error_number;
            return T105_RECEIVE_FAILED;
        }
        ++stats->datagrams_seen;
        if (received != (ssize_t)d.payload_length || !t105_datagram_matches(&d, e)) {
            ++stats->datagrams_rejected;
            continue;
        }
        /* A readable socket is not proof that recvmsg/processing finished
         * inside the window. Recheck time immediately before consuming the
         * one-shot reply and before calling the send operation. */
        now = io->monotonic_ms(ctx);
        if (now < 0) { stats->receive_errno = EIO; return T105_RECEIVE_FAILED; }
        if (now < previous_now) {
            stats->receive_errno = ERANGE;
            return T105_RECEIVE_FAILED;
        }
        previous_now = now;
        if (now >= deadline) {
            ++stats->datagrams_rejected;
            return T105_TIMED_OUT;
        }
        /* Consume before the OS send. An error is final and is never retried. */
        session->response_consumed = 1;
        stats->send_attempted = 1;
        error_number = 0;
        received = io->send_reply(ctx, e, e->nonce, &error_number);
        if (received != (ssize_t)T105_NONCE_BYTES) {
            stats->send_errno = received < 0 ? error_number : EIO;
            return T105_LOCAL_SEND_FAILED;
        }
        stats->local_send_accepted = 1;
        return T105_LOCAL_SEND_ACCEPTED;
    }
    return T105_REQUEST_REJECTED_LIMIT;
}

const char *t105_status_name(T105Status status)
{
    switch (status) {
    case T105_UNARMED: return "not_armed";
    case T105_TIMED_OUT: return "timeout";
    case T105_REQUEST_REJECTED_LIMIT: return "request_limit_reached";
    case T105_LOCAL_SEND_ACCEPTED: return "local_send_accepted";
    case T105_LOCAL_SEND_FAILED: return "local_send_failed";
    case T105_RECEIVE_FAILED: return "receive_failed";
    case T105_ALREADY_USED: return "already_used";
    }
    return "unknown";
}
