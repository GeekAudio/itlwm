#ifndef TEST089_RADIOTAP_PARSER_H
#define TEST089_RADIOTAP_PARSER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define T089_PACKET_OTHERHOST 3U
#define T089_PACKET_OUTGOING 4U

enum t089_parse_result {
    T089_PARSE_INVALID = 0,
    T089_PARSE_VALID = 1,
    T089_PARSE_UNSUPPORTED = 2
};

struct t089_observation {
    size_t radiotap_length;
    size_t mpdu_length;
    size_t mpdu_offset;
    bool has_radiotap_flags;
    uint8_t radiotap_flags;
    bool has_tx_flags;
    uint16_t tx_flags;
    bool has_data_retries;
    uint8_t data_retries;
    bool exact_probe_match;
    uint16_t wifi_sequence;
    uint16_t awdl_sequence;
    bool is_host_driver_completion_candidate;
    bool is_outgoing_echo;
    bool is_other_matching_packet;
};

/* Parse one radiotap-prefixed packet and compare its MPDU with sent_mpdu. */
enum t089_parse_result t089_parse_observation(
    const uint8_t *packet, size_t packet_length, unsigned packet_type,
    const uint8_t sent_mpdu[96], struct t089_observation *out);

#endif
