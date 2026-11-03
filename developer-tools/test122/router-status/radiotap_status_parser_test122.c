/* SPDX-License-Identifier: GPL-2.0-only */
/* Offline parser regression for Test122's bounded TX-status classifier. */
#define main test122_sender_entry
#include "awdl_router_status_sender_test122.c"
#undef main

#define CHECK(condition, label) do { \
    if (!(condition)) { fprintf(stderr, "FAIL %s\n", label); return 1; } \
} while (0)

static bool make_test_set(struct packet_set *set) {
    memset(set, 0, sizeof(*set));
    set->wifi_sequence_base = 0x0ffeU;
    set->awdl_sequence_base = 0xfffeU;
    static const uint8_t nonce[WIRE_NONCE_LEN] =
        {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    memcpy(set->wire_nonce, nonce, sizeof(nonce));
    if (inet_pton(AF_INET6, "fe80::1122", &set->source_ip) != 1 ||
        inet_pton(AF_INET6, "fe80::aabb", &set->target_ip) != 1) return false;
    static const uint8_t source_mac[6] = {0x02,0x11,0x22,0x33,0x44,0x55};
    static const uint8_t target_mac[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    memcpy(set->source_mac, source_mac, sizeof(source_mac));
    memcpy(set->target_mac, target_mac, sizeof(target_mac));
    for (unsigned ordinal = 0; ordinal < FRAME_COUNT; ++ordinal) {
        uint8_t *packet = set->bytes + HEADER_LEN + ordinal * PACKET_LEN;
        memcpy(packet, rtap_noack_clear, RTAP_LEN);
        if (!build_expected_mpdu(set, ordinal, packet + RTAP_LEN)) return false;
    }
    return true;
}

int main(void) {
    CHECK(capture_loss_free_state(true,false,false,false,false,0,0,0)==-1,
          "missing_kernel_stats_is_unknown");
    CHECK(capture_loss_free_state(true,false,false,true,false,0,0,0)==0,
          "known_truncation_is_not_unknown");
    CHECK(capture_loss_free_state(false,false,false,false,true,4,0,4)==0,
          "unfinished_window_is_lossy_or_incomplete");
    CHECK(capture_loss_free_state(true,false,false,false,true,4,0,4)==1,
          "complete_equal_kernel_and_user_counts_is_clean");
    CHECK(capture_loss_free_state(true,false,false,false,true,4,1,4)==0,
          "kernel_drop_is_not_loss_free");

    struct packet_set set;
    CHECK(make_test_set(&set), "build_dynamic_packetset_fixture");

    /* The bases deliberately cross both sequence-number wrap boundaries. */
    const unsigned expected_wifi[FRAME_COUNT] = {0x0ffeU,0x0fffU,0U,1U};
    const unsigned expected_awdl[FRAME_COUNT] = {0xfffeU,0xffffU,0U,1U};
    for (unsigned ordinal = 0; ordinal < FRAME_COUNT; ++ordinal) {
        const uint8_t *frame = set.bytes + HEADER_LEN + ordinal * PACKET_LEN;
        struct t089_observation parsed;
        CHECK(t089_parse_observation(frame, PACKET_LEN, T089_PACKET_OUTGOING,
                                    frame + RTAP_LEN, &parsed) == T089_PARSE_VALID,
              "dynamic_frame_radiotap_parse");
        CHECK(exact_frame_ordinal(frame, PACKET_LEN, &parsed, &set) == (int)ordinal,
              "dynamic_exact_frame_maps_ordinal");
        CHECK(le16(frame + RTAP_LEN + 22U) == expected_wifi[ordinal] << 4,
              "sequence_control_wrap_and_fragment_zero");
        CHECK(le16(frame + RTAP_LEN + 34U) == expected_awdl[ordinal],
              "awdl_sequence_wrap");
        CHECK(memcmp(frame + RTAP_LEN + 88U, set.wire_nonce, WIRE_NONCE_LEN) == 0,
              "nonce_is_in_each_frame");
    }

    /* The shared T089 parser checks shape/fields; this wrapper performs the
     * new run-nonce/sequence comparison independently of its old marker. */
    const unsigned ordinal = 2U;
    const uint8_t *expected_packet = set.bytes + HEADER_LEN + ordinal * PACKET_LEN;
    uint8_t outgoing[STATUS_RAW_BYTES] = {0};
    memcpy(outgoing, expected_packet, PACKET_LEN);
    struct t089_observation parsed;
    CHECK(t089_parse_observation(outgoing, PACKET_LEN, T089_PACKET_OUTGOING,
                                expected_packet + RTAP_LEN, &parsed) == T089_PARSE_VALID,
          "outgoing_radiotap_parse");
    CHECK(parsed.has_tx_flags && parsed.tx_flags == 0x0010U &&
          !parsed.has_data_retries,
          "outgoing_radiotap_fields");
    CHECK(exact_frame_ordinal(outgoing, PACKET_LEN, &parsed, &set) == (int)ordinal,
          "outgoing_exact_ordinal");
    int matched = -1;
    CHECK(!is_status_candidate(outgoing, PACKET_LEN, T089_PACKET_OUTGOING,
                              &parsed, &set, &matched),
          "outgoing_not_completion_candidate");

    /* A status frame may change a header byte; it still needs this run's
     * nonce, full sequence-control (fragment included), and AWDL sequence. */
    static const uint8_t status_rtap[11] = {
        0x00,0x00,0x0b,0x00,0x00,0x80,0x02,0x00,0x10,0x00,0x03
    };
    uint8_t status_packet[STATUS_RAW_BYTES] = {0};
    memcpy(status_packet, status_rtap, sizeof(status_rtap));
    uint8_t changed[MPDU_LEN];
    memcpy(changed, expected_packet + RTAP_LEN, sizeof(changed));
    changed[2] ^= 0x01U;
    memcpy(status_packet + sizeof(status_rtap), changed, sizeof(changed));
    CHECK(t089_parse_observation(status_packet, sizeof(status_rtap) + MPDU_LEN,
                                T089_PACKET_OTHERHOST,
                                expected_packet + RTAP_LEN, &parsed) == T089_PARSE_VALID,
          "status_radiotap_parse");
    CHECK(parsed.has_tx_flags && parsed.tx_flags == 0x0010U && parsed.has_data_retries &&
          parsed.data_retries == 3U,
          "status_radiotap_fields");
    CHECK(exact_frame_ordinal(status_packet, sizeof(status_rtap) + MPDU_LEN,
                              &parsed, &set) == -1,
          "changed_header_not_exact");
    matched = -1;
    CHECK(is_status_candidate(status_packet, sizeof(status_rtap) + MPDU_LEN,
                              T089_PACKET_OTHERHOST, &parsed, &set, &matched) &&
          matched == (int)ordinal,
          "nonce_and_full_sequences_bind_status_to_ordinal");
    CHECK(probe_ordinal_from_sequences(status_packet,
                                       sizeof(status_rtap) + MPDU_LEN,
                                       &parsed, &set) == (int)ordinal,
          "correlated_sequence_lookup");

    uint8_t wrong_nonce[STATUS_RAW_BYTES];
    memcpy(wrong_nonce, status_packet, sizeof(status_rtap) + MPDU_LEN);
    wrong_nonce[sizeof(status_rtap) + 88U] ^= 0x80U;
    CHECK(t089_parse_observation(wrong_nonce, sizeof(status_rtap) + MPDU_LEN,
                                T089_PACKET_OTHERHOST,
                                expected_packet + RTAP_LEN, &parsed) == T089_PARSE_VALID &&
          !is_status_candidate(wrong_nonce, sizeof(status_rtap) + MPDU_LEN,
                               T089_PACKET_OTHERHOST, &parsed, &set, NULL),
          "wrong_run_nonce_rejected");

    uint8_t wrong_sc[STATUS_RAW_BYTES];
    memcpy(wrong_sc, status_packet, sizeof(status_rtap) + MPDU_LEN);
    wrong_sc[sizeof(status_rtap) + 22U] ^= 0x10U;
    CHECK(t089_parse_observation(wrong_sc, sizeof(status_rtap) + MPDU_LEN,
                                T089_PACKET_OTHERHOST,
                                expected_packet + RTAP_LEN, &parsed) == T089_PARSE_VALID &&
          !is_status_candidate(wrong_sc, sizeof(status_rtap) + MPDU_LEN,
                               T089_PACKET_OTHERHOST, &parsed, &set, NULL),
          "wrong_sequence_control_rejected");

    uint8_t wrong_fragment[STATUS_RAW_BYTES];
    memcpy(wrong_fragment, status_packet, sizeof(status_rtap) + MPDU_LEN);
    wrong_fragment[sizeof(status_rtap) + 22U] |= 0x01U;
    CHECK(t089_parse_observation(wrong_fragment, sizeof(status_rtap) + MPDU_LEN,
                                T089_PACKET_OTHERHOST,
                                expected_packet + RTAP_LEN, &parsed) == T089_PARSE_VALID &&
          !is_status_candidate(wrong_fragment, sizeof(status_rtap) + MPDU_LEN,
                               T089_PACKET_OTHERHOST, &parsed, &set, NULL),
          "nonzero_fragment_rejected");

    uint8_t wrong_awdl[STATUS_RAW_BYTES];
    memcpy(wrong_awdl, status_packet, sizeof(status_rtap) + MPDU_LEN);
    wrong_awdl[sizeof(status_rtap) + 34U] ^= 0x01U;
    CHECK(t089_parse_observation(wrong_awdl, sizeof(status_rtap) + MPDU_LEN,
                                T089_PACKET_OTHERHOST,
                                expected_packet + RTAP_LEN, &parsed) == T089_PARSE_VALID &&
          !is_status_candidate(wrong_awdl, sizeof(status_rtap) + MPDU_LEN,
                               T089_PACKET_OTHERHOST, &parsed, &set, NULL),
          "wrong_awdl_sequence_rejected");

    struct t089_observation no_retries = parsed;
    no_retries.has_data_retries = false;
    CHECK(!is_status_candidate(status_packet, sizeof(status_rtap) + MPDU_LEN,
                               T089_PACKET_OTHERHOST, &no_retries, &set, NULL),
          "status_without_retry_field_rejected");

    /* FCS metadata remains supported; parser failures remain fail-closed. */
    uint8_t fcs_packet[STATUS_RAW_BYTES] = {0};
    const uint8_t fcs_rtap[12] = {
        0x00,0x00,0x0c,0x00,0x02,0x80,0x00,0x00,0x10,0x00,0x10,0x00
    };
    memcpy(fcs_packet, fcs_rtap, sizeof(fcs_rtap));
    memcpy(fcs_packet + sizeof(fcs_rtap), expected_packet + RTAP_LEN, MPDU_LEN);
    memset(fcs_packet + sizeof(fcs_rtap) + MPDU_LEN, 0xa5, 4);
    CHECK(t089_parse_observation(fcs_packet, sizeof(fcs_rtap) + MPDU_LEN + 4,
                                T089_PACKET_OUTGOING,
                                expected_packet + RTAP_LEN, &parsed) == T089_PARSE_VALID &&
          parsed.has_radiotap_flags && (parsed.radiotap_flags & 0x10U) &&
          parsed.mpdu_length == MPDU_LEN &&
          exact_frame_ordinal(fcs_packet, sizeof(fcs_rtap) + MPDU_LEN + 4,
                              &parsed, &set) == (int)ordinal,
          "radiotap_fcs_handling");

    uint8_t unsupported[8 + MPDU_LEN] = {0};
    unsupported[2] = 8;
    unsupported[7] = 0x40; /* unknown vendor namespace */
    memcpy(unsupported + 8, expected_packet + RTAP_LEN, MPDU_LEN);
    CHECK(t089_parse_observation(unsupported, sizeof(unsupported),
                                T089_PACKET_OTHERHOST,
                                expected_packet + RTAP_LEN, &parsed) == T089_PARSE_UNSUPPORTED,
          "unknown_vendor_namespace_fails_closed");
    CHECK(t089_parse_observation(outgoing, 7, T089_PACKET_OUTGOING,
                                expected_packet + RTAP_LEN, &parsed) == T089_PARSE_INVALID,
          "truncated_radiotap_fails_closed");
    uint8_t bad_len[RTAP_LEN + MPDU_LEN];
    memcpy(bad_len, outgoing, sizeof(bad_len));
    bad_len[2] = 0xff;
    bad_len[3] = 0x00;
    CHECK(t089_parse_observation(bad_len, sizeof(bad_len),
                                T089_PACKET_OUTGOING,
                                expected_packet + RTAP_LEN, &parsed) == T089_PARSE_INVALID,
          "radiotap_length_overrun_fails_closed");

    puts("PASS Test122 radiotap status parser and run-bound attribution");
    return 0;
}
