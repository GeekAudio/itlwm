#include "probe_frame.h"
#include "radiotap_parser.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void put_le16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)(value & 0xffU);
    p[1] = (uint8_t)(value >> 8);
}

static void put_le32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)(value & 0xffU);
    p[1] = (uint8_t)((value >> 8) & 0xffU);
    p[2] = (uint8_t)((value >> 16) & 0xffU);
    p[3] = (uint8_t)(value >> 24);
}

static size_t make_status_packet(uint8_t *out, const uint8_t *mpdu,
                                 bool include_flags, bool include_retries,
                                 bool preceding_channel, bool include_fcs) {
    uint32_t present = 0U;
    size_t rt_len;
    size_t pos = 8U;
    memset(out, 0, 256U);
    out[0] = 0U;
    out[1] = 0U;
    if (preceding_channel || include_fcs) present |= UINT32_C(1) << 1;
    if (preceding_channel) present |= UINT32_C(1) << 3;
    if (include_flags) present |= UINT32_C(1) << 15;
    if (include_retries) present |= UINT32_C(1) << 17;
    put_le32(out + 4U, present);
    if (preceding_channel || include_fcs)
        out[pos++] = include_fcs ? 0x10U : 0x20U; /* FLAGS */
    if (preceding_channel) {
        if ((pos & 1U) != 0U) pos++;
        out[pos++] = 0x6cU; /* CHANNEL frequency LE */
        out[pos++] = 0x16U;
        out[pos++] = 0x80U; /* 5 GHz OFDM flags */
        out[pos++] = 0x00U;
    }
    if (include_flags) {
        if ((pos & 1U) != 0U) pos++;
        put_le16(out + pos, 0U); /* zero is deliberately not an ACK claim */
        pos += 2U;
    }
    if (include_retries) out[pos++] = 0U;
    rt_len = pos;
    put_le16(out + 2U, (uint16_t)rt_len);
    memcpy(out + rt_len, mpdu, T089_MPDU_LENGTH);
    if (include_fcs) memset(out + rt_len + T089_MPDU_LENGTH, 0xa5, 4U);
    return rt_len + T089_MPDU_LENGTH + (include_fcs ? 4U : 0U);
}

static void test_exact_probe_build_matches_contract(void) {
    static const uint8_t expected_radiotap[10] = {
        0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x00, 0x00, 0x18, 0x00
    };
    uint8_t packet[T089_PACKET_LENGTH];
    t089_build_probe(packet);
    assert(memcmp(packet, expected_radiotap, sizeof(expected_radiotap)) == 0);
    assert(packet[10U + 22U] == 0x30U && packet[10U + 23U] == 0x12U);
    assert(packet[10U + 34U] == 0x01U && packet[10U + 35U] == 0x86U);
    assert(memcmp(packet + 10U + 88U, "T086RX01", 8U) == 0);
}

static void test_otherhost_with_both_status_fields_is_candidate(void) {
    uint8_t probe[T089_PACKET_LENGTH];
    uint8_t packet[256];
    struct t089_observation observation;
    size_t length;
    t089_build_probe(probe);
    length = make_status_packet(packet, probe + T089_RADIOTAP_LENGTH,
                                true, true, false, false);
    assert(t089_parse_observation(packet, length, T089_PACKET_OTHERHOST,
                                  probe + T089_RADIOTAP_LENGTH,
                                  &observation) == T089_PARSE_VALID);
    assert(observation.exact_probe_match);
    assert(observation.is_host_driver_completion_candidate);
    assert(!observation.is_outgoing_echo);
    assert(observation.has_tx_flags && observation.tx_flags == 0U);
    assert(observation.has_data_retries && observation.data_retries == 0U);
    assert(observation.wifi_sequence == 291U);
    assert(observation.awdl_sequence == 34305U);
}

static void test_outgoing_echo_is_not_tx_status(void) {
    uint8_t probe[T089_PACKET_LENGTH];
    struct t089_observation observation;
    t089_build_probe(probe);
    assert(t089_parse_observation(probe, sizeof(probe), T089_PACKET_OUTGOING,
                                  probe + T089_RADIOTAP_LENGTH,
                                  &observation) == T089_PARSE_VALID);
    assert(observation.exact_probe_match);
    assert(observation.is_outgoing_echo);
    assert(!observation.is_host_driver_completion_candidate);
    assert(observation.has_tx_flags && observation.tx_flags == 0x18U);
    assert(!observation.has_data_retries);
}

static void test_status_fields_on_other_packet_type_are_not_candidate(void) {
    uint8_t probe[T089_PACKET_LENGTH];
    uint8_t packet[256];
    struct t089_observation observation;
    size_t length;
    t089_build_probe(probe);
    length = make_status_packet(packet, probe + T089_RADIOTAP_LENGTH,
                                true, true, false, false);
    assert(t089_parse_observation(packet, length, 0U,
                                  probe + T089_RADIOTAP_LENGTH,
                                  &observation) == T089_PARSE_VALID);
    assert(observation.exact_probe_match);
    assert(!observation.is_host_driver_completion_candidate);
    assert(!observation.is_outgoing_echo);
    assert(observation.is_other_matching_packet);
}

static void test_alignment_and_missing_field_fail_closed(void) {
    uint8_t probe[T089_PACKET_LENGTH];
    uint8_t packet[256];
    struct t089_observation observation;
    size_t length;
    t089_build_probe(probe);
    length = make_status_packet(packet, probe + T089_RADIOTAP_LENGTH,
                                true, true, true, false);
    assert(t089_parse_observation(packet, length, T089_PACKET_OTHERHOST,
                                  probe + T089_RADIOTAP_LENGTH,
                                  &observation) == T089_PARSE_VALID);
    assert(observation.is_host_driver_completion_candidate);
    assert(observation.radiotap_length == 17U);

    length = make_status_packet(packet, probe + T089_RADIOTAP_LENGTH,
                                true, false, false, false);
    assert(t089_parse_observation(packet, length, T089_PACKET_OTHERHOST,
                                  probe + T089_RADIOTAP_LENGTH,
                                  &observation) == T089_PARSE_VALID);
    assert(observation.exact_probe_match);
    assert(!observation.is_host_driver_completion_candidate);
    assert(observation.is_other_matching_packet);
}

static void test_mismatch_and_malformed_headers_are_not_candidates(void) {
    uint8_t probe[T089_PACKET_LENGTH];
    uint8_t packet[256];
    struct t089_observation observation;
    size_t length;
    t089_build_probe(probe);
    length = make_status_packet(packet, probe + T089_RADIOTAP_LENGTH,
                                true, true, false, false);
    packet[length - 1U] ^= 1U;
    assert(t089_parse_observation(packet, length, T089_PACKET_OTHERHOST,
                                  probe + T089_RADIOTAP_LENGTH,
                                  &observation) == T089_PARSE_VALID);
    assert(!observation.exact_probe_match);
    assert(!observation.is_host_driver_completion_candidate);

    packet[2] = 7U;
    packet[3] = 0U;
    assert(t089_parse_observation(packet, length, T089_PACKET_OTHERHOST,
                                  probe + T089_RADIOTAP_LENGTH,
                                  &observation) == T089_PARSE_INVALID);
}

static void test_exact_length_and_declared_fcs_handling(void) {
    uint8_t probe[T089_PACKET_LENGTH];
    uint8_t packet[256];
    struct t089_observation observation;
    size_t length;
    t089_build_probe(probe);
    length = make_status_packet(packet, probe + T089_RADIOTAP_LENGTH,
                                true, true, false, true);
    assert(t089_parse_observation(packet, length, T089_PACKET_OTHERHOST,
                                  probe + T089_RADIOTAP_LENGTH,
                                  &observation) == T089_PARSE_VALID);
    assert(observation.has_radiotap_flags);
    assert((observation.radiotap_flags & 0x10U) != 0U);
    assert(observation.mpdu_length == T089_MPDU_LENGTH);
    assert(observation.exact_probe_match);
    assert(observation.is_host_driver_completion_candidate);

    /* Undeclared tail bytes are not silently ignored as an exact MPDU. */
    length = make_status_packet(packet, probe + T089_RADIOTAP_LENGTH,
                                true, true, false, false);
    memset(packet + length, 0, 4U);
    assert(t089_parse_observation(packet, length + 4U, T089_PACKET_OTHERHOST,
                                  probe + T089_RADIOTAP_LENGTH,
                                  &observation) == T089_PARSE_VALID);
    assert(!observation.exact_probe_match);
    assert(!observation.is_host_driver_completion_candidate);
}

int main(void) {
    test_exact_probe_build_matches_contract();
    test_otherhost_with_both_status_fields_is_candidate();
    test_outgoing_echo_is_not_tx_status();
    test_status_fields_on_other_packet_type_are_not_candidate();
    test_alignment_and_missing_field_fail_closed();
    test_mismatch_and_malformed_headers_are_not_candidates();
    test_exact_length_and_declared_fcs_handling();
    puts("test089 host parser/frame checks passed");
    return 0;
}
