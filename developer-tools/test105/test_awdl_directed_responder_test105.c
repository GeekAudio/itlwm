/* SPDX-License-Identifier: GPL-2.0-only */
#include "awdl_directed_responder_test105.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    T105Datagram packets[T105_MAX_DATAGRAMS + 2u];
    size_t count;
    size_t next;
    int64_t now_ms;
    int64_t receive_clock_delta_ms;
    int send_calls;
    ssize_t send_result;
    int send_error;
    uint8_t sent_payload[T105_NONCE_BYTES];
} Fake;

static void require(int ok, const char *name)
{
    if (!ok) {
        fprintf(stderr, "FAIL %s\n", name);
        exit(1);
    }
}

static int fake_wait(void *opaque, int timeout_ms)
{
    Fake *fake = opaque;
    if (fake->next < fake->count) return 1;
    fake->now_ms += timeout_ms;
    return 0;
}

static ssize_t fake_receive(void *opaque, T105Datagram *out, int *error_number)
{
    Fake *fake = opaque;
    (void)error_number;
    if (fake->next >= fake->count) return -1;
    *out = fake->packets[fake->next++];
    fake->now_ms += fake->receive_clock_delta_ms;
    return (ssize_t)out->payload_length;
}

static ssize_t fake_send(void *opaque, const T105Expected *expected,
                         const uint8_t payload[T105_NONCE_BYTES], int *error_number)
{
    Fake *fake = opaque;
    (void)expected;
    ++fake->send_calls;
    memcpy(fake->sent_payload, payload, T105_NONCE_BYTES);
    *error_number = fake->send_error;
    return fake->send_result;
}

static int64_t fake_clock(void *opaque)
{
    return ((Fake *)opaque)->now_ms;
}

static const T105Io fake_io = {
    .wait_readable = fake_wait,
    .receive = fake_receive,
    .send_reply = fake_send,
    .monotonic_ms = fake_clock
};

static const T105Expected expected = {
    .peer_ipv6 = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                   0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55 },
    .local_ipv6 = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                    0x02, 0xaa, 0xbb, 0xff, 0xfe, 0xcc, 0xdd, 0xee },
    .nonce = { 1, 2, 3, 4, 5, 6, 7, 8 },
    .ifindex = 17
};

static T105Datagram matching_packet(void)
{
    T105Datagram datagram;
    memset(&datagram, 0, sizeof(datagram));
    memcpy(datagram.payload, expected.nonce, T105_NONCE_BYTES);
    memcpy(datagram.source_ipv6, expected.peer_ipv6, sizeof(datagram.source_ipv6));
    memcpy(datagram.destination_ipv6, expected.local_ipv6,
           sizeof(datagram.destination_ipv6));
    datagram.payload_length = T105_NONCE_BYTES;
    datagram.source_scope_id = expected.ifindex;
    datagram.source_port = T105_REQUEST_PORT;
    datagram.destination_port = T105_REPLY_PORT;
    datagram.ifindex = expected.ifindex;
    datagram.hop_limit = 1;
    datagram.pktinfo_present = 1;
    datagram.hop_limit_present = 1;
    return datagram;
}

static void reset_fake(Fake *fake)
{
    memset(fake, 0, sizeof(*fake));
    fake->now_ms = 1000;
    fake->send_result = (ssize_t)T105_NONCE_BYTES;
}

static T105Status run_once(Fake *fake, T105Session *session, T105Stats *stats)
{
    return t105_reply_once(&fake_io, fake, &expected, session, 100, stats);
}

static void test_valid_request_replies_once(void)
{
    Fake fake;
    T105Session session = { 1, 0, 0 };
    T105Stats stats;

    reset_fake(&fake);
    fake.count = 2;
    fake.packets[0] = matching_packet();
    fake.packets[1] = matching_packet();
    require(run_once(&fake, &session, &stats) == T105_LOCAL_SEND_ACCEPTED,
            "valid status");
    require(fake.send_calls == 1 && stats.send_attempted && stats.local_send_accepted,
            "one send");
    require(memcmp(fake.sent_payload, expected.nonce, T105_NONCE_BYTES) == 0,
            "same nonce");
    require(session.response_consumed, "consume once");
}

static void test_mismatches_never_send(void)
{
    enum {
        WRONG_NONCE, SHORT_PAYLOAD, LONG_PAYLOAD, PAYLOAD_TRUNCATED,
        CONTROL_TRUNCATED, MISSING_PKTINFO, MISSING_HOPLIMIT,
        WRONG_IFINDEX, WRONG_HOPLIMIT, WRONG_SCOPE, WRONG_SOURCE_PORT,
        WRONG_DESTINATION_PORT, WRONG_SOURCE, WRONG_DESTINATION, CASE_COUNT
    };
    int case_id;

    for (case_id = 0; case_id < CASE_COUNT; ++case_id) {
        Fake fake;
        T105Session session = { 1, 0, 0 };
        T105Stats stats;
        T105Datagram datagram = matching_packet();
        switch (case_id) {
        case WRONG_NONCE: datagram.payload[0] ^= 1; break;
        case SHORT_PAYLOAD: datagram.payload_length = 7; break;
        case LONG_PAYLOAD: datagram.payload_length = 9; break;
        case PAYLOAD_TRUNCATED: datagram.payload_truncated = 1; break;
        case CONTROL_TRUNCATED: datagram.control_truncated = 1; break;
        case MISSING_PKTINFO: datagram.pktinfo_present = 0; break;
        case MISSING_HOPLIMIT: datagram.hop_limit_present = 0; break;
        case WRONG_IFINDEX: ++datagram.ifindex; break;
        case WRONG_HOPLIMIT: ++datagram.hop_limit; break;
        case WRONG_SCOPE: ++datagram.source_scope_id; break;
        case WRONG_SOURCE_PORT: ++datagram.source_port; break;
        case WRONG_DESTINATION_PORT: ++datagram.destination_port; break;
        case WRONG_SOURCE: datagram.source_ipv6[15] ^= 1; break;
        case WRONG_DESTINATION: datagram.destination_ipv6[15] ^= 1; break;
        default: break;
        }
        reset_fake(&fake);
        fake.count = 1;
        fake.packets[0] = datagram;
        require(run_once(&fake, &session, &stats) == T105_TIMED_OUT,
                "mismatch times out");
        require(fake.send_calls == 0 && !stats.send_attempted, "mismatch no send");
    }
}

static void test_mismatch_then_valid_and_bounded_input(void)
{
    Fake fake;
    T105Session session = { 1, 0, 0 };
    T105Stats stats;
    T105Datagram datagram = matching_packet();

    reset_fake(&fake);
    datagram.payload[0] ^= 1;
    fake.packets[0] = datagram;
    fake.packets[1] = matching_packet();
    fake.count = 2;
    require(run_once(&fake, &session, &stats) == T105_LOCAL_SEND_ACCEPTED,
            "valid after mismatch");
    require(stats.datagrams_seen == 2 && stats.datagrams_rejected == 1 &&
            fake.send_calls == 1, "bounded matching");

    reset_fake(&fake);
    session.armed = 1;
    session.attempted = 0;
    session.response_consumed = 0;
    datagram = matching_packet();
    ++datagram.hop_limit;
    fake.count = T105_MAX_DATAGRAMS;
    for (size_t i = 0; i < fake.count; ++i) fake.packets[i] = datagram;
    require(run_once(&fake, &session, &stats) == T105_REQUEST_REJECTED_LIMIT,
            "packet budget");
    require(fake.send_calls == 0 && stats.datagrams_seen == T105_MAX_DATAGRAMS,
            "budget no send");
}

static void test_send_failure_is_final(void)
{
    Fake fake;
    T105Session session = { 1, 0, 0 };
    T105Stats stats;

    reset_fake(&fake);
    fake.count = 1;
    fake.packets[0] = matching_packet();
    fake.send_result = -1;
    fake.send_error = EHOSTUNREACH;
    require(run_once(&fake, &session, &stats) == T105_LOCAL_SEND_FAILED,
            "send error status");
    require(fake.send_calls == 1 && stats.send_attempted &&
            !stats.local_send_accepted, "single failed send");
    require(stats.send_errno == EHOSTUNREACH && session.response_consumed,
            "failure consumed");
    require(run_once(&fake, &session, &stats) == T105_ALREADY_USED,
            "no retry status");
    require(fake.send_calls == 1, "no retry call");

    reset_fake(&fake);
    session.armed = 1;
    session.attempted = 0;
    session.response_consumed = 0;
    fake.count = 1;
    fake.packets[0] = matching_packet();
    fake.send_result = 4;
    require(run_once(&fake, &session, &stats) == T105_LOCAL_SEND_FAILED,
            "partial send failure");
    require(fake.send_calls == 1 && !stats.local_send_accepted,
            "partial send not accepted");
}

static void test_nonce_arm_and_timeout(void)
{
    Fake fake;
    T105Session session = { 0, 0, 0 };
    T105Stats stats;
    uint8_t nonce[T105_NONCE_BYTES] = { 0 };

    reset_fake(&fake);
    require(!t105_nonce_is_usable(nonce), "zero nonce rejected");
    memcpy(nonce, "T086RX01", T105_NONCE_BYTES);
    require(!t105_nonce_is_usable(nonce), "static marker rejected");
    nonce[0] = 1;
    require(t105_nonce_is_usable(nonce), "explicit nonce accepted");
    require(run_once(&fake, &session, &stats) == T105_UNARMED &&
            fake.send_calls == 0, "disarmed no send");

    session.armed = 1;
    require(run_once(&fake, &session, &stats) == T105_TIMED_OUT &&
            fake.send_calls == 0, "quiet timeout");
    require(run_once(&fake, &session, &stats) == T105_ALREADY_USED &&
            fake.send_calls == 0, "timeout cannot rearm same session");
}

static void test_receive_finishing_after_deadline_does_not_send(void)
{
    Fake fake;
    T105Session session = { 1, 0, 0 };
    T105Stats stats;

    reset_fake(&fake);
    fake.count = 1;
    fake.packets[0] = matching_packet();
    fake.receive_clock_delta_ms = 100;
    require(run_once(&fake, &session, &stats) == T105_TIMED_OUT,
            "receive finished at deadline");
    require(fake.send_calls == 0 && !stats.send_attempted &&
            !session.response_consumed, "late receive no send");
}

static void test_monotonic_clock_rollback_does_not_send(void)
{
    Fake fake;
    T105Session session = { 1, 0, 0 };
    T105Stats stats;

    reset_fake(&fake);
    fake.count = 1;
    fake.packets[0] = matching_packet();
    fake.receive_clock_delta_ms = -1;
    require(run_once(&fake, &session, &stats) == T105_RECEIVE_FAILED,
            "clock rollback status");
    require(stats.receive_errno == ERANGE && fake.send_calls == 0 &&
            !stats.send_attempted, "clock rollback no send");
}

int main(void)
{
    test_valid_request_replies_once();
    test_mismatches_never_send();
    test_mismatch_then_valid_and_bounded_input();
    test_send_failure_is_final();
    test_nonce_arm_and_timeout();
    test_receive_finishing_after_deadline_does_not_send();
    test_monotonic_clock_rollback_does_not_send();
    puts("PASS test105 offline responder contract");
    return 0;
}
