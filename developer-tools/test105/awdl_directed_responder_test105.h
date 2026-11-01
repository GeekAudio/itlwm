/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef AWDL_DIRECTED_RESPONDER_TEST105_H
#define AWDL_DIRECTED_RESPONDER_TEST105_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define T105_NONCE_BYTES 8u
#define T105_REQUEST_PORT 49152u
#define T105_REPLY_PORT 49153u
#define T105_MAX_DATAGRAMS 16u

typedef struct {
    uint8_t peer_ipv6[16];
    uint8_t local_ipv6[16];
    uint8_t nonce[T105_NONCE_BYTES];
    uint32_t ifindex;
} T105Expected;

/* A normalized recvmsg result. Production code fills this only after checking
 * cmsg uniqueness, exact ancillary lengths, source sockaddr, and msg_flags. */
typedef struct {
    uint8_t payload[T105_NONCE_BYTES];
    size_t payload_length;
    uint8_t source_ipv6[16];
    uint8_t destination_ipv6[16];
    uint32_t source_scope_id;
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t ifindex;
    int hop_limit;
    int pktinfo_present;
    int hop_limit_present;
    int payload_truncated;
    int control_truncated;
} T105Datagram;

typedef enum {
    T105_UNARMED = 0,
    T105_TIMED_OUT,
    T105_REQUEST_REJECTED_LIMIT,
    T105_LOCAL_SEND_ACCEPTED,
    T105_LOCAL_SEND_FAILED,
    T105_RECEIVE_FAILED,
    T105_ALREADY_USED
} T105Status;

typedef struct {
    uint32_t datagrams_seen;
    uint32_t datagrams_rejected;
    int send_attempted;
    int local_send_accepted;
    int send_errno;
    int receive_errno;
} T105Stats;

typedef struct {
    int (*wait_readable)(void *context, int timeout_ms);
    ssize_t (*receive)(void *context, T105Datagram *datagram, int *error_number);
    ssize_t (*send_reply)(void *context, const T105Expected *expected,
                          const uint8_t payload[T105_NONCE_BYTES],
                          int *error_number);
    int64_t (*monotonic_ms)(void *context);
} T105Io;

typedef struct {
    int armed;
    int attempted;
    int response_consumed;
} T105Session;

int t105_nonce_is_usable(const uint8_t nonce[T105_NONCE_BYTES]);
int t105_datagram_matches(const T105Datagram *datagram,
                          const T105Expected *expected);
T105Status t105_reply_once(const T105Io *io, void *context,
                           const T105Expected *expected, T105Session *session,
                           int timeout_ms, T105Stats *stats);
const char *t105_status_name(T105Status status);

#endif
