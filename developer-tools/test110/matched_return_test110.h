/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MATCHED_RETURN_TEST110_H
#define MATCHED_RETURN_TEST110_H

#include <stdint.h>

/* Configure receive ancillary data and verify the already-bound UDP socket.
 * This function never creates, binds, sends on, or closes a socket. */
int t110_prepare_existing_socket(int fd, const uint8_t local_ipv6[16],
                                 uint32_t ifindex, int *error_number);

/* Sample the same mach_absolute_time uptime domain used to compare the kernel
 * clock_get_uptime lease deadline. */
int t110_current_uptime_us(uint64_t *now_us);

/* Receive at most one matching eight-byte echo on that same socket. The wait
 * is bounded by both timeout_ms (1..100) and the kernel uptime deadline, in
 * the clock_get_uptime microsecond domain. No send/retry is performed here. */
int t110_wait_for_matching_return(
    int fd, const uint8_t peer_ipv6[16], const uint8_t local_ipv6[16],
    uint32_t ifindex, const uint8_t nonce[8], uint64_t kernel_deadline_us,
    uint32_t timeout_ms,
    uint32_t *datagrams_seen, uint32_t *datagrams_rejected,
    int32_t *receive_error, uint64_t *elapsed_us);

/* Pure packet predicate for offline tests. */
typedef struct {
    uint8_t payload[8];
    uint32_t payload_length;
    uint8_t source_ipv6[16];
    uint8_t destination_ipv6[16];
    uint32_t source_scope_id;
    uint32_t ifindex;
    uint16_t source_port;
    uint16_t destination_port;
    int32_t hop_limit;
    uint8_t pktinfo_present;
    uint8_t hop_limit_present;
    uint8_t payload_truncated;
    uint8_t control_truncated;
    uint8_t ancillary_valid;
} T110Datagram;

typedef struct {
    uint8_t peer_ipv6[16];
    uint8_t local_ipv6[16];
    uint8_t nonce[8];
    uint32_t ifindex;
} T110Expected;

int t110_datagram_matches(const T110Datagram *datagram,
                          const T110Expected *expected);

#endif
